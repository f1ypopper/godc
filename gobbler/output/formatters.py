from typing import Any

from gobbler.utils.ownership import is_app_function, is_library_function

LOW_SIGNAL_TARGET_PREFIXES = (
    "runtime.convT",
    "runtime.typeAssert",
    "runtime.gopanic",
    "runtime.print",
    "runtime.duff",
    "runtime.wbMove",
    "sync.(*Mutex)",
    "sync.(*RWMutex)",
)
HIGH_SIGNAL_OP_KINDS = {
    "call_user",
    "start_goroutine",
    "callback",
    "file_read",
    "file_write",
    "file_open",
    "file_create",
    "directory_create",
    "permission_change",
    "environment_read",
    "environment_write",
    "http_network",
    "http_request",
    "http_get",
    "http_post",
    "network_connect",
    "network_listen",
    "process_launch",
    "crypto_random",
    "aes_crypto",
    "cipher_crypto",
    "base64_decode_or_encode",
    "hex_decode_or_encode",
    "gzip_compression",
    "zlib_compression",
    "stream_read",
    "map_write",
    "string_to_bytes",
    "bytes_to_string",
    "make_slice",
    "make_map",
    "make_channel",
    "channel_send",
    "channel_receive",
}


def format_graph(
    graph: dict[str, list[Any]],
    semantics: dict[str, Any] | None = None,
    *,
    compact: bool = False,
    max_functions: int | None = None,
) -> str:
    call_args = _index_call_arguments(semantics)
    indirect_calls = _index_indirect_calls(semantics)
    lines = []
    shown_functions = 0
    for function, calls in sorted(
        graph.items(), key=lambda item: (not is_app_function(item[0]), item[0])
    ):
        visible_calls = [
            call
            for call in calls
            if call.visible and (not compact or is_reportable_call(function, call))
        ]
        if compact and not visible_calls and not is_app_function(function):
            continue
        if max_functions is not None and shown_functions >= max_functions:
            lines.append("... truncated raw call graph ...")
            break
        lines.append(function)
        if not visible_calls:
            lines.append("  <no direct calls>")
            shown_functions += 1
            continue
        for call in visible_calls:
            address = hex(call.address)
            lines.append(f"  {address} -> {call.display()}")
            if not compact:
                for detail in _format_call_details(
                    call_args.get((function, address)),
                    indirect_calls.get((function, address)),
                ):
                    lines.append(f"    {detail}")
        shown_functions += 1
    return "\n".join(lines)


def format_behavior_report(semantics: dict[str, Any]) -> str:
    lines = ["Behavior summary"]
    hints = semantics.get("assessment_hints") or []
    if hints:
        lines.append("  assessment_hints:")
        for hint in hints:
            lines.append(f"    - {hint}")

    lines.extend(format_behavior_story_summary(semantics))

    behavior_ir = semantics.get("behavior_ir") or {}
    if behavior_ir:
        summary = behavior_ir.get("summary") or {}
        lines.append("  compressed_flow:")
        lines.append(
            "    - "
            f"functions={summary.get('function_count', 0)} "
            f"operations={summary.get('operation_count', 0)} "
            f"edges={summary.get('edge_count', 0)} "
            f"static_data_functions={summary.get('functions_with_static_data', 0)}"
        )
        for function, item in selected_behavior_functions(behavior_ir):
            lines.append(f"    {function}")
            tags = [tag for tag in item.get("tags", []) if is_reportable_tag(tag)]
            if tags:
                lines.append(f"      tags: {', '.join(tags[:10])}")
            for operation in selected_operations(item):
                lines.append(f"      {format_operation(operation)}")

    lines.extend(format_runtime_decoding_summary(semantics))
    lines.extend(format_recovered_indicators_summary(semantics))
    lines.extend(format_semantic_chains_summary(semantics))
    lines.extend(format_capability_summary(semantics))
    lines.extend(format_app_interesting_functions(semantics))
    return "\n".join(lines)


def format_behavior_story_summary(semantics: dict[str, Any]) -> list[str]:
    story = semantics.get("behavior_story") or {}
    if not story:
        return []
    lines = ["  evaluator_behavior:"]
    summary = story.get("summary") or {}
    lines.append(
        "    - "
        f"actions={summary.get('action_count', 0)} "
        f"network={summary.get('network_action_count', 0)} "
        f"filesystem={summary.get('filesystem_action_count', 0)} "
        f"process_or_execution={summary.get('process_or_execution_action_count', 0)} "
        f"embedded_artifacts={summary.get('embedded_artifact_action_count', 0)}"
    )
    narrative = story.get("narrative") or []
    if narrative:
        lines.append("    narrative:")
        for item in narrative[:6]:
            lines.append(f"      - {item}")

    artifacts = story.get("artifacts") or {}
    if artifacts:
        lines.append("    artifacts:")
        for key in ("urls", "commands", "paths", "files", "embedded_artifacts", "decoded_artifacts"):
            values = artifacts.get(key) or []
            if not values:
                continue
            rendered = ", ".join(format_story_artifact(item) for item in values[:5])
            lines.append(f"      - {key}: {rendered}")

    actions = story.get("actions") or []
    if actions:
        lines.append("    flow:")
        for action in actions[:18]:
            artifact_text = ""
            artifacts = action.get("artifacts") or []
            if artifacts:
                artifact_text = " artifacts=[" + "; ".join(format_story_artifact(item) for item in artifacts[:4]) + "]"
            target = action.get("target_api") or ""
            target_text = f" target={target}" if target else ""
            lines.append(
                "      - "
                f"{action.get('function')} {action.get('category')}/{action.get('kind')} "
                f"{action.get('description')} confidence={action.get('confidence', 'medium')}"
                f"{target_text}{artifact_text}"
            )
    return lines


def format_story_artifact(item: Any) -> str:
    if not isinstance(item, dict):
        return shorten_literal(item, 120)
    value = item.get("value") or item.get("type") or item
    prefix = item.get("type")
    text = shorten_literal(value, 120)
    if prefix:
        return f"{prefix}={text!r}"
    return repr(text)


def _index_call_arguments(
    semantics: dict[str, Any] | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if not semantics:
        return {}
    functions = (semantics.get("dataflow") or {}).get("functions") or {}
    indexed = {}
    for function, facts in functions.items():
        for call_args in facts.get("call_arguments", []):
            address = call_args.get("address")
            if address:
                indexed[(function, address)] = call_args
    return indexed


def _index_indirect_calls(
    semantics: dict[str, Any] | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if not semantics:
        return {}
    indexed = {}
    for indirect_call in semantics.get("indirect_calls", []) or []:
        function = indirect_call.get("function")
        address = indirect_call.get("address")
        if function and address:
            indexed[(function, address)] = indirect_call
    return indexed


def _format_call_details(
    call_args: dict[str, Any] | None,
    indirect_call: dict[str, Any] | None,
) -> list[str]:
    details = []
    if indirect_call:
        classification = indirect_call.get("classification")
        operand = indirect_call.get("operand")
        indirect_parts = ["indirect"]
        if classification:
            indirect_parts.append(f"classification={classification}")
        if operand:
            indirect_parts.append(f"operand={operand}")
        details.append(" ".join(indirect_parts))
        evidence = indirect_call.get("evidence") or []
        if evidence:
            details.append(f"evidence: {'; '.join(evidence)}")
        provenance = _format_provenance(indirect_call.get("provenance") or {})
        if provenance:
            details.append(f"target_source: {provenance}")

    if call_args:
        args = call_args.get("args") or []
        if args:
            details.append("args:")
            for arg in args:
                details.append(f"  {arg.get('reg', '?')}: {_format_arg_value(arg)}")
        string_args = call_args.get("string_args") or []
        if string_args:
            rendered = ", ".join(repr(arg) for arg in string_args)
            details.append(f"strings: {rendered}")
        slice_args = call_args.get("slice_args") or []
        if slice_args:
            details.append("slices:")
            for slice_arg in slice_args:
                details.append(f"  {_format_slice_arg(slice_arg)}")
    return details


def _format_arg_value(arg: Any) -> str:
    if not isinstance(arg, dict):
        return hex(arg) if isinstance(arg, int) else str(arg)

    kind = arg.get("kind") or "unknown"
    label = arg.get("label")
    pieces = [kind]
    if label is not None:
        pieces.append(str(label))
    if arg.get("address"):
        pieces.append(f"@ {arg['address']}")
    elif arg.get("value") is not None and label is None:
        pieces.append(hex(arg["value"]) if isinstance(arg["value"], int) else str(arg["value"]))

    metadata = arg.get("metadata") or {}
    if metadata.get("field_offset"):
        pieces.append(f"field={metadata['field_offset']}")
    if metadata.get("offset"):
        pieces.append(f"offset={metadata['offset']}")
    if metadata.get("section"):
        pieces.append(f"section={metadata['section']}")
    if metadata.get("entropy") is not None:
        pieces.append(f"entropy={metadata['entropy']}")
    if metadata.get("call_address"):
        pieces.append(f"from_call={metadata['call_address']}")

    base_value = metadata.get("base_value")
    if base_value:
        pieces.append(f"base={_format_nested_value(base_value)}")
    return " ".join(pieces)


def _format_nested_value(value: dict[str, Any]) -> str:
    kind = value.get("kind") or "unknown"
    label = value.get("label")
    address = value.get("address")
    rendered = f"{kind}:{label}" if label is not None else kind
    if address:
        rendered = f"{rendered}@{address}"
    metadata = value.get("metadata") or {}
    base_value = metadata.get("base_value")
    if base_value:
        rendered = f"{rendered} base={_format_nested_value(base_value)}"
    return rendered


def _format_provenance(provenance: dict[str, Any]) -> str:
    if not provenance:
        return ""
    pieces = []
    if provenance.get("kind"):
        pieces.append(provenance["kind"])
    if provenance.get("instruction"):
        pieces.append(f"instruction={provenance['instruction']}")
    if provenance.get("base"):
        pieces.append(f"base={provenance['base']}")
    if provenance.get("index"):
        pieces.append(f"index={provenance['index']}")
    if provenance.get("disp"):
        pieces.append(f"disp={provenance['disp']}")
    if provenance.get("memory_kind"):
        pieces.append(f"memory={provenance['memory_kind']}")
    return " ".join(pieces)


def _format_slice_arg(slice_arg: dict[str, Any]) -> str:
    reg = slice_arg.get("reg") or "?"
    data = slice_arg.get("data") or {}
    length = slice_arg.get("length") or {}
    capacity = slice_arg.get("capacity") or {}
    return (
        f"{reg}: data={_format_arg_value(data)} "
        f"len={_format_arg_value(length)} cap={_format_arg_value(capacity)}"
    )


def selected_behavior_functions(behavior_ir: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    functions = behavior_ir.get("functions") or {}
    selected = []
    for function, item in sorted(
        functions.items(), key=lambda pair: (not is_app_function(pair[0]), pair[0])
    ):
        if not is_app_function(function):
            continue
        if selected_operations(item):
            selected.append((function, item))
    return selected[:40]


def selected_operations(item: dict[str, Any]) -> list[dict[str, Any]]:
    operations = []
    for operation in item.get("flow", []):
        if operation.get("kind") not in HIGH_SIGNAL_OP_KINDS:
            continue
        target = operation.get("target", "")
        if target.startswith(LOW_SIGNAL_TARGET_PREFIXES):
            continue
        if operation.get("kind") == "call_user" and not (
            is_app_function(target) or is_capability_target(target)
        ):
            continue
        operations.append(operation)
    return operations[:14]


def format_operation(operation: dict[str, Any]) -> str:
    pieces = [
        operation.get("address", "?"),
        operation.get("kind", "operation"),
        "->",
        operation.get("target", "?"),
    ]
    strings = operation.get("string_args") or []
    arg_strings = [
        item.get("value")
        for item in (operation.get("arguments") or {}).get("strings", [])
        if isinstance(item, dict) and usable_string(item.get("value"))
    ]
    values = []
    source_values = strings if strings else arg_strings
    for value in source_values:
        if usable_string(value) and value not in values:
            values.append(value)
    asset_values = [value for value in values if looks_like_asset_or_path(value)]
    if asset_values:
        values = asset_values
    if values:
        rendered = ", ".join(repr(value) for value in values[:4])
        pieces.append(f"strings=[{rendered}]")
    return " ".join(pieces)


def format_capability_summary(semantics: dict[str, Any]) -> list[str]:
    behavior_ir = semantics.get("behavior_ir") or {}
    functions = behavior_ir.get("functions") or {}
    capabilities: dict[str, set[str]] = {}
    for function, item in functions.items():
        if not is_app_function(function):
            continue
        for operation in item.get("flow", []):
            for tag in operation.get("tags", []):
                if tag in {"user_behavior", "argument_flow", "type_init", "allocation"}:
                    continue
                capabilities.setdefault(tag, set()).add(function)
    if not capabilities:
        return []
    lines = ["  capabilities:"]
    for tag, owners in sorted(capabilities.items()):
        lines.append(f"    - {tag}: {', '.join(sorted(owners)[:6])}")
    return lines


def format_runtime_decoding_summary(semantics: dict[str, Any]) -> list[str]:
    runtime_decoding = semantics.get("runtime_decoding") or {}
    functions = runtime_decoding.get("functions") or []
    if not functions:
        return []
    lines = ["  runtime_decoding:"]
    summary = runtime_decoding.get("summary") or {}
    lines.append(
        "    - "
        f"functions={summary.get('function_count', 0)} "
        f"explicit_decoder_api={summary.get('explicit_decoder_api_count', 0)} "
        f"encoder_api={summary.get('encoder_api_count', 0)} "
        f"custom_candidates={summary.get('custom_decoder_candidate_count', 0)} "
        f"runtime_materializers={summary.get('runtime_string_materialization_count', 0)} "
        f"recovered_indicators={summary.get('recovered_indicator_count', 0)}"
    )
    for item in functions[:12]:
        evidence = ",".join(item.get("evidence", [])[:5])
        labels = ",".join(item.get("feature_labels", [])[:6]) or "<none>"
        lines.append(
            "    - "
            f"{item['function']} classification={item['classification']} "
            f"labels={labels} confidence={item['confidence']} evidence={evidence}"
        )
        for recovery in item.get("static_source_recoveries", [])[:3]:
            preview = recovery.get("preview") or {}
            text = preview.get("text")
            if not text:
                continue
            lines.append(
                "      "
                f"static_source={recovery.get('source')} @ {recovery.get('address')} "
                f"{preview.get('encoding')} type={preview.get('indicator_type')} "
                f"text={shorten_literal(text)!r}"
            )
        for caller in item.get("literal_callers", [])[:3]:
            values = ", ".join(repr(value) for value in caller.get("strings", [])[:4])
            lines.append(
                "      "
                f"called_by={caller['caller']} @ {caller['address']} strings=[{values}]"
            )
            for preview in caller.get("decoded_previews", [])[:2]:
                transform_text = format_recovery_transforms(preview.get("transforms") or [])
                type_text = (
                    f" type={preview['indicator_type']}"
                    if preview.get("indicator_type") and preview.get("indicator_type") != "text"
                    else ""
                )
                text = preview.get("text")
                if text:
                    lines.append(
                        "      "
                        f"{preview['encoding']}_decoded len={preview['decoded_length']}{type_text} "
                        f"text={shorten_literal(text)!r}{transform_text}"
                    )
                    continue
                lines.append(
                    "      "
                    f"{preview['encoding']}_decoded len={preview['decoded_length']} "
                    f"ascii={preview['ascii_preview']!r} hex={preview['hex_preview']}{transform_text}"
                )
    return lines


def format_recovered_indicators_summary(semantics: dict[str, Any]) -> list[str]:
    runtime_decoding = semantics.get("runtime_decoding") or {}
    indicators = runtime_decoding.get("recovered_indicators") or []
    if not indicators:
        return []
    lines = ["  recovered_indicators:"]
    for indicator in indicators[:20]:
        transform_text = format_recovery_transforms(indicator.get("transforms") or [])
        lines.append(
            "    - "
            f"{indicator.get('type', 'indicator')}={shorten_literal(indicator.get('value', ''), 160)!r} "
            f"producer={indicator.get('producer')} "
            f"caller={indicator.get('caller')} "
            f"confidence={indicator.get('confidence', 'medium')}{transform_text}"
        )
        for consumer in indicator.get("consumed_by", [])[:5]:
            sinks = ", ".join(format_chain_endpoint(sink) for sink in consumer.get("sinks", [])[:4])
            if not sinks:
                continue
            lines.append(
                "      "
                f"consumed_by={consumer.get('function')} "
                f"chain={consumer.get('chain_kind')} sinks=[{sinks}] "
                f"link={consumer.get('link_type')}"
            )
    return lines


def format_recovery_transforms(transforms: list[dict[str, Any]]) -> str:
    if not transforms:
        return ""
    pieces = []
    for transform in transforms[:4]:
        kind = transform.get("kind", "?")
        if transform.get("key") is not None:
            pieces.append(f"{kind}(key={transform['key']!r})")
        else:
            pieces.append(kind)
    return f" transforms=[{', '.join(pieces)}]"


def format_semantic_chains_summary(semantics: dict[str, Any]) -> list[str]:
    semantic_chains = semantics.get("semantic_chains") or {}
    chains = semantic_chains.get("chains") or []
    if not chains:
        return []
    summary = semantic_chains.get("summary") or {}
    by_kind = summary.get("by_kind") or {}
    kind_counts = ", ".join(f"{kind}={count}" for kind, count in sorted(by_kind.items())[:10])
    lines = ["  semantic_chains:"]
    lines.append(
        "    - "
        f"chains={summary.get('chain_count', 0)} "
        f"high_confidence={summary.get('high_confidence_count', 0)} "
        f"kinds={kind_counts}"
    )
    for chain in chains[:16]:
        fields = chain.get("related_fields") or []
        literals = chain.get("literals") or []
        sinks = chain.get("sinks") or []
        sink_text = ", ".join(format_chain_endpoint(sink) for sink in sinks[:4])
        pieces = [
            f"{chain['kind']} function={chain['function']}",
            f"confidence={chain['confidence']}",
        ]
        if sink_text:
            pieces.append(f"sinks=[{sink_text}]")
        if fields:
            pieces.append(f"fields={fields[:8]}")
        if literals:
            pieces.append(f"literals={[shorten_literal(value) for value in literals[:4]]}")
        lines.append(f"    - {' '.join(pieces)}")
    return lines


def format_chain_endpoint(item: dict[str, Any]) -> str:
    target = item.get("target") or "?"
    kind = item.get("kind") or "?"
    address = item.get("address")
    if address:
        return f"{kind}:{target}@{address}"
    return f"{kind}:{target}"


def shorten_literal(value: Any, limit: int = 80) -> str:
    value = str(value)
    return value if len(value) <= limit else value[: limit - 3] + "..."


def format_app_interesting_functions(semantics: dict[str, Any]) -> list[str]:
    interesting = [
        item
        for item in semantics.get("interesting_functions") or []
        if is_app_function(item.get("function", ""))
    ]
    if not interesting:
        return []
    lines = ["  high_signal_app_functions:"]
    for item in interesting[:12]:
        lines.append(
            "    - "
            f"{item['function']} score={item['score']} "
            f"reasons={'; '.join(item['reasons'][:6])}"
        )
    return lines


def is_reportable_call(function: str, call: Any) -> bool:
    target = call.target
    if target.startswith(LOW_SIGNAL_TARGET_PREFIXES):
        return False
    if is_app_function(function):
        return (
            is_app_function(target)
            or is_capability_target(target)
            or bool(getattr(call, "string_args", []))
        )
    return is_app_function(target) or is_capability_target(target)


def is_capability_target(target: str) -> bool:
    needles = (
        "os.",
        "net/",
        "net/http",
        "http.",
        "crypto/",
        "encoding/",
        "compress/",
        "syscall.",
        "windows.(*LazyProc).Call",
        "embed.FS",
        "io.ReadAll",
        "image.Decode",
        "filepath.",
        "path/filepath.",
    )
    return any(needle in target for needle in needles)


def is_reportable_tag(tag: str) -> bool:
    return tag not in {
        "argument_flow",
        "type_init",
        "allocation",
        "reads_struct_fields",
        "reads_go_string_fields",
        "uses_static_data",
    }


def usable_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) < 2 or len(value) > 200:
        return False
    lowered = value.lower()
    if any(
        marker in lowered
        for marker in (
            "avx",
            "sse",
            "popcnt",
            "xmm",
            "ymm",
            "zmm",
            "fma",
            "bmi",
        )
    ):
        return False
    if any(ord(ch) < 9 for ch in value):
        return False
    # Drop common register-pair false positives from adjacent Go string data.
    alpha = sum(ch.isalpha() for ch in value)
    if len(value) >= 8 and alpha / len(value) > 0.85 and not any(
        marker in value for marker in ("/", "\\", ".", "%", ":", "-", "_", " ")
    ):
        return False
    return True


def looks_like_asset_or_path(value: str) -> bool:
    lowered = value.lower()
    return (
        "/" in value
        or "\\" in value
        or lowered.endswith(
            (
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".ico",
                ".bmp",
                ".dll",
                ".exe",
                ".dat",
                ".json",
                ".txt",
            )
        )
    )


def format_semantics(semantics: dict[str, Any]) -> str:
    lines = ["Semantic analysis"]
    hints = semantics.get("assessment_hints") or []
    if hints:
        lines.append("  assessment_hints:")
        for hint in hints:
            lines.append(f"    - {hint}")

    timing = semantics.get("analysis_timing") or {}
    if timing:
        pass_text = ", ".join(
            f"{item.get('name')}={item.get('duration_seconds')}s"
            for item in (timing.get("passes") or [])[:12]
        )
        lines.append(
            "  analysis_timing:"
            f" total={timing.get('total_seconds')}s"
            + (f" passes=[{pass_text}]" if pass_text else "")
        )

    transfers = semantics.get("mid_function_control_transfers") or []
    transfers = [
        transfer
        for transfer in transfers
        if transfer.get("classification") != "go_runtime_duff_helper"
    ]
    if transfers:
        lines.append("  mid_function_control_transfers:")
        for transfer in transfers[:10]:
            lines.append(
                "    - "
                f"{transfer['display']} "
                f"classification={transfer['classification']}"
            )

    indirect_calls = semantics.get("indirect_calls") or []
    if indirect_calls:
        lines.append("  indirect_calls:")
        for indirect_call in indirect_calls[:10]:
            lines.append(
                "    - "
                f"{indirect_call['display']} "
                f"evidence={'; '.join(indirect_call['evidence'])}"
            )

    constants = semantics.get("global_constants") or {}
    strings = constants.get("global_strings") or []
    if strings:
        lines.append("  global_strings:")
        for string in strings[:10]:
            value = string["value"]
            if len(value) > 120:
                value = value[:117] + "..."
            lines.append(
                "    - "
                f"{string['address']} len={string['length']} "
                f"classification={string['classification']} value={value!r}"
            )

    arrays = constants.get("constant_arrays") or []
    if arrays:
        lines.append("  constant_arrays:")
        for array in arrays[:10]:
            dump_path = f" dump={array['dump_path']}" if array.get("dump_path") else ""
            lines.append(
                "    - "
                f"{array['id']} {array['section']}:{array['va']} size={array['size']} "
                f"entropy={array['entropy']} reasons={','.join(array['reasons'])}{dump_path}"
            )

    blobs = semantics.get("notable_data_blobs") or []
    if blobs:
        lines.append("  notable_data_blobs:")
        for blob in blobs[:10]:
            refs = ", ".join(blob["referenced_by"]) or "<none>"
            duplicates = (
                f" duplicates={blob['duplicate_count']}"
                if blob.get("duplicate_count", 1) > 1
                else ""
            )
            lines.append(
                "    - "
                f"{blob['id']} {blob['section']}:{blob['va']} size={blob['size']} "
                f"entropy={blob['entropy']} reasons={','.join(blob['reasons'])} refs={refs}{duplicates}"
            )

    transformers = semantics.get("data_transformers") or []
    transformers = [
        transformer
        for transformer in transformers
        if is_app_function(transformer.get("function", ""))
        or transformer.get("input_sources")
        or transformer.get("confidence") == "high"
    ]
    if transformers:
        lines.append("  data_transformers:")
        for transformer in transformers[:10]:
            lines.append(
                "    - "
                f"{transformer['function']} ops={','.join(transformer['operations'])} "
                f"confidence={transformer['confidence']} sources={','.join(transformer['input_sources']) or '<unknown>'}"
            )

    loaders = semantics.get("loader_behaviors") or []
    loaders = [
        loader
        for loader in loaders
        if loader.get("function") == "<reachable_component>"
        or is_app_function(loader.get("function", ""))
        or loader.get("confidence") == "high"
    ]
    if loaders:
        lines.append("  loader_behaviors:")
        for loader in loaders[:10]:
            lines.append(
                "    - "
                f"{loader['function']} kind={loader['kind']} confidence={loader['confidence']} "
                f"evidence={','.join(loader['evidence'])}"
            )

    dataflow = semantics.get("dataflow") or {}
    if dataflow:
        summary = dataflow.get("summary") or {}
        lines.append("  dataflow:")
        lines.append(
            "    - "
            f"functions={summary.get('function_count', 0)} "
            f"call_args={summary.get('call_argument_count', 0)} "
            f"value_flows={summary.get('value_flow_count', 0)} "
            f"struct_fields={summary.get('struct_field_access_count', 0)} "
            f"string_fields={summary.get('string_field_candidate_count', 0)} "
            f"slice_args={summary.get('slice_arg_candidate_count', 0)}"
        )
        shown = 0
        for function, facts in (dataflow.get("functions") or {}).items():
            for flow in facts.get("value_flows", []):
                lines.append(
                    "    - "
                    f"{function}: {flow['from_kind']}:{flow['from']} "
                    f"--{flow['reg']}--> {flow['to']} @ {flow['address']}"
                )
                shown += 1
                if shown >= 10:
                    break
            if shown >= 10:
                break

    semantic_chains = semantics.get("semantic_chains") or {}
    if semantic_chains:
        summary = semantic_chains.get("summary") or {}
        lines.append("  semantic_chains:")
        lines.append(
            "    - "
            f"chains={summary.get('chain_count', 0)} "
            f"high_confidence={summary.get('high_confidence_count', 0)} "
            f"kinds={summary.get('by_kind', {})}"
        )
        for chain in (semantic_chains.get("chains") or [])[:12]:
            sinks = ", ".join(format_chain_endpoint(sink) for sink in chain.get("sinks", [])[:3])
            lines.append(
                "    - "
                f"{chain['kind']} {chain['function']} confidence={chain['confidence']} "
                f"sinks={sinks or '<none>'}"
            )

    cfg = semantics.get("cfg") or {}
    if cfg:
        summary = cfg.get("summary") or {}
        lines.append("  cfg:")
        lines.append(
            "    - "
            f"functions={summary.get('function_count', 0)} "
            f"blocks={summary.get('block_count', 0)} "
            f"edges={summary.get('edge_count', 0)} "
            f"loops={summary.get('loop_count', 0)} "
            f"transform_loops={summary.get('probable_transform_loop_count', 0)}"
        )
        shown = 0
        for function, facts in (cfg.get("functions") or {}).items():
            for loop in facts.get("probable_transform_loops", []):
                ops = ",".join(loop.get("evidence", {}).get("transform_ops", []))
                lines.append(
                    "    - "
                    f"{function}: {loop['classification']} {loop['start']}-{loop['end']} ops={ops}"
                )
                shown += 1
                if shown >= 10:
                    break
            if shown >= 10:
                break

    interesting = semantics.get("interesting_functions") or []
    interesting = [
        item
        for item in interesting
        if is_app_function(item.get("function", ""))
        or any(
            reason.startswith(("transforms_embedded_artifact", "passes_embedded_artifact_to_loader"))
            for reason in item.get("reasons", [])
        )
    ]
    if interesting:
        lines.append("  interesting_functions:")
        for item in interesting[:10]:
            lines.append(
                "    - "
                f"{item['function']} score={item['score']} reasons={'; '.join(item['reasons'][:5])}"
            )

    behavior_graph = semantics.get("behavior_graph") or {}
    if behavior_graph:
        summary = behavior_graph.get("summary") or {}
        lines.append("  behavior_graph:")
        lines.append(
            "    - "
            f"nodes={summary.get('node_count', 0)} edges={summary.get('edge_count', 0)}"
        )
        interesting_edges = [
            edge
            for edge in behavior_graph.get("edges", [])
            if edge["type"]
            in {
                "input_to_transformer",
                "transforms_into",
                "source_for_embedded_artifact",
                "passed_to_loader",
                "feeds_loader",
                "invokes_behavior",
            }
        ]
        for edge in interesting_edges[:15]:
            lines.append(
                "    - "
                f"{edge['from']} --{edge['type']}--> {edge['to']}"
            )

    behavior_ir = semantics.get("behavior_ir") or {}
    if behavior_ir:
        summary = behavior_ir.get("summary") or {}
        lines.append("  behavior_ir:")
        lines.append(
            "    - "
            f"functions={summary.get('function_count', 0)} "
            f"operations={summary.get('operation_count', 0)} "
            f"edges={summary.get('edge_count', 0)} "
            f"static_data_functions={summary.get('functions_with_static_data', 0)} "
            f"type_activity_functions={summary.get('functions_with_type_activity', 0)} "
            f"transform_loop_functions={summary.get('functions_with_transform_loops', 0)}"
        )
        shown = 0
        for function, item in (behavior_ir.get("functions") or {}).items():
            for operation in item.get("flow", []):
                lines.append(
                    "    - "
                    f"{function}: {operation['address']} "
                    f"{operation['kind']} -> {operation['target']}"
                )
                shown += 1
                if shown >= 15:
                    break
            if shown >= 15:
                break

    runtime_decoding = semantics.get("runtime_decoding") or {}
    if runtime_decoding:
        summary = runtime_decoding.get("summary") or {}
        lines.append("  runtime_decoding:")
        lines.append(
            "    - "
            f"functions={summary.get('function_count', 0)} "
            f"explicit_decoder_api={summary.get('explicit_decoder_api_count', 0)} "
            f"custom_candidates={summary.get('custom_decoder_candidate_count', 0)} "
            f"runtime_materializers={summary.get('runtime_string_materialization_count', 0)}"
        )
        for item in (runtime_decoding.get("functions") or [])[:10]:
            labels = ",".join(item.get("feature_labels", [])[:6]) or "<none>"
            lines.append(
                "    - "
                f"{item['function']} {item['classification']} "
                f"labels={labels} confidence={item['confidence']} "
                f"evidence={','.join(item.get('evidence', [])[:5])}"
            )
    return "\n".join(lines)


def format_human_readable_report(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> str:
    return (
        f"{format_behavior_report(semantics)}\n\n"
        f"{format_semantics(semantics)}\n\n"
        "Filtered reachable call graph\n"
        f"{format_graph(graph, semantics, compact=True, max_functions=90)}\n"
    )
