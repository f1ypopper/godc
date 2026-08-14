from typing import Any

from gobbler.passes.behavior_graph import classify_call_behavior
from gobbler.utils.noise import RUNTIME_NOISE_PREFIXES, is_runtime_noise_call


IMPORTANT_RUNTIME_CALLS = {
    "runtime.newobject": ("allocate_object", "allocation"),
    "runtime.newarray": ("allocate_array", "allocation"),
    "runtime.makeslice": ("make_slice", "allocation"),
    "runtime.makeslicecopy": ("make_slice_copy", "allocation"),
    "runtime.growslice": ("grow_slice", "allocation"),
    "runtime.makemap": ("make_map", "allocation"),
    "runtime.mapassign": ("map_write", "type_init"),
    "runtime.makechan": ("make_channel", "concurrency"),
    "runtime.chansend": ("channel_send", "concurrency"),
    "runtime.chanrecv": ("channel_receive", "concurrency"),
    "runtime.newproc": ("start_goroutine", "concurrency"),
    "runtime.slicebytetostring": ("bytes_to_string", "type_init"),
    "runtime.stringtoslicebyte": ("string_to_bytes", "type_init"),
    "runtime.concatstring": ("string_concat", "type_init"),
    "runtime.convTstring": ("box_string", "type_init"),
    "runtime.convTslice": ("box_slice", "type_init"),
}

MAX_FLOW_OPS_PER_FUNCTION = 120
MAX_DATA_ITEMS_PER_FUNCTION = 80


def build_behavior_ir(
    analyzer: Any, graph: dict[str, list[Any]], semantics: dict[str, Any]
) -> dict[str, Any]:
    builder = BehaviorIRBuilder(analyzer, graph, semantics)
    return builder.build()


class BehaviorIRBuilder:
    def __init__(self, analyzer: Any, graph: dict[str, list[Any]], semantics: dict[str, Any]):
        self.analyzer = analyzer
        self.graph = graph
        self.semantics = semantics
        self.call_args = self._index_call_args()

    def build(self) -> dict[str, Any]:
        functions = {}
        edges = []
        for function_name, calls in self.graph.items():
            item = self._function_ir(function_name, calls)
            functions[function_name] = item
            edges.extend(item["edges"])

        return {
            "version": 1,
            "purpose": "compressed_user_behavior_flow",
            "noise_policy": {
                "kept": [
                    "user-defined calls",
                    "behavioral standard-library/API calls",
                    "important Go runtime allocation/type/concurrency calls",
                    "constant data and typed argument evidence",
                    "loop/transform summaries",
                ],
                "dropped_prefixes": list(RUNTIME_NOISE_PREFIXES),
            },
            "summary": self._summary(functions, edges),
            "functions": functions,
            "edges": edges,
        }

    def _function_ir(self, function_name: str, calls: list[Any]) -> dict[str, Any]:
        flow = []
        edges = []
        tags = set()

        for call in calls:
            operation = self._operation_for_call(function_name, call)
            if operation is None:
                continue
            flow.append(operation)
            tags.update(operation["tags"])
            if operation["kind"] in {"call_user", "start_goroutine", "callback"}:
                edges.append(
                    {
                        "from": function_name,
                        "to": operation["target"],
                        "type": operation["kind"],
                        "address": operation["address"],
                    }
                )

        data = self._function_data(function_name)
        type_activity = self._type_activity(function_name)
        control = self._control_summary(function_name)
        if data["strings"] or data["constant_arrays"] or data["data_blobs"]:
            tags.add("uses_static_data")
        if type_activity["struct_field_reads"]:
            tags.add("reads_struct_fields")
        if type_activity["string_field_candidates"]:
            tags.add("reads_go_string_fields")
        if type_activity["slice_arguments"]:
            tags.add("passes_slices")
        if control["probable_transform_loops"]:
            tags.add("has_transform_loop")

        return {
            "entry": self._function_entry(function_name),
            "tags": sorted(tags),
            "flow": flow[:MAX_FLOW_OPS_PER_FUNCTION],
            "data": data,
            "type_activity": type_activity,
            "control": control,
            "edges": edges,
        }

    def _operation_for_call(self, function_name: str, call: Any) -> dict[str, Any] | None:
        address = hex(call.address)
        args = self.call_args.get((function_name, address), {})
        target = call.target

        if call.via and "runtime.newproc" in call.via:
            return self._operation(
                "start_goroutine",
                target,
                address,
                call,
                args,
                ["concurrency", "user_behavior"],
                via=call.via,
            )

        if call.via and call.kind == "user":
            return self._operation(
                "callback",
                target,
                address,
                call,
                args,
                ["callback", "user_behavior"],
                via=call.via,
            )

        runtime_kind = classify_runtime_call(target)
        if runtime_kind is not None:
            action, category = runtime_kind
            return self._operation(action, target, address, call, args, [category])

        if is_noise_call(target):
            return None

        if call.kind == "user":
            return self._operation(
                "call_user", target, address, call, args, ["user_behavior"]
            )

        behavior = classify_call_behavior(target)
        if behavior is not None:
            action, category = behavior
            return self._operation(action, target, address, call, args, [category, action])

        if args and has_interesting_args(args):
            return self._operation(
                "call_with_semantic_args",
                target,
                address,
                call,
                args,
                ["argument_flow"],
            )

        return None

    def _operation(
        self,
        kind: str,
        target: str,
        address: str,
        call: Any,
        args: dict[str, Any],
        tags: list[str],
        via: str | None = None,
    ) -> dict[str, Any]:
        operation = {
            "address": address,
            "kind": kind,
            "target": target,
            "tags": sorted(set(tags)),
        }
        if via:
            operation["via"] = via
        if call.string_args:
            operation["string_args"] = call.string_args
        semantic_args = compress_call_args(args)
        if semantic_args:
            operation["arguments"] = semantic_args
        return operation

    def _function_data(self, function_name: str) -> dict[str, Any]:
        constants = self.semantics.get("global_constants") or {}
        strings = [
            {
                "address": item.get("address"),
                "classification": item.get("classification"),
                "value": item.get("value"),
            }
            for item in constants.get("global_strings") or []
            if function_name in item.get("referenced_by", [])
            and item.get("classification") != "string"
        ]
        arrays = [
            {
                "id": item.get("id"),
                "section": item.get("section"),
                "va": item.get("va"),
                "size": item.get("size"),
                "entropy": item.get("entropy"),
                "reasons": item.get("reasons", []),
                "ascii_preview": item.get("ascii_preview"),
                "magic_offsets": item.get("magic_offsets", []),
            }
            for item in constants.get("constant_arrays") or []
            if function_name in item.get("referenced_by", [])
        ]
        blobs = [
            {
                "id": item.get("id"),
                "section": item.get("section"),
                "va": item.get("va"),
                "size": item.get("size"),
                "entropy": item.get("entropy"),
                "reasons": item.get("reasons", []),
                "magic_offsets": item.get("magic_offsets", []),
            }
            for item in self.semantics.get("suspicious_data_blobs") or []
            if function_name in item.get("referenced_by", [])
        ]
        return {
            "strings": strings[:MAX_DATA_ITEMS_PER_FUNCTION],
            "constant_arrays": arrays[:MAX_DATA_ITEMS_PER_FUNCTION],
            "data_blobs": blobs[:MAX_DATA_ITEMS_PER_FUNCTION],
        }

    def _type_activity(self, function_name: str) -> dict[str, Any]:
        facts = (
            (self.semantics.get("dataflow") or {})
            .get("functions", {})
            .get(function_name, {})
        )
        slice_args = []
        for call in facts.get("call_arguments", []):
            for slice_arg in call.get("slice_args", []):
                slice_args.append({"call": call.get("target"), "address": call.get("address"), **slice_arg})
        return {
            "struct_field_reads": facts.get("struct_field_accesses", [])[:50],
            "string_field_candidates": facts.get("string_field_candidates", [])[:50],
            "slice_arguments": slice_args[:50],
        }

    def _control_summary(self, function_name: str) -> dict[str, Any]:
        facts = (
            (self.semantics.get("cfg") or {})
            .get("functions", {})
            .get(function_name, {})
        )
        return {
            "block_count": facts.get("block_count", 0),
            "edge_count": facts.get("edge_count", 0),
            "loop_count": facts.get("loop_count", 0),
            "probable_transform_loops": facts.get("probable_transform_loops", [])[:20],
        }

    def _function_entry(self, function_name: str) -> str | None:
        function = self.analyzer.user_by_name.get(function_name)
        if function is None:
            for candidate in self.analyzer.user_functions:
                if candidate.get("FullName") == function_name:
                    function = candidate
                    break
        if function is None:
            return None
        return hex(function["Start"])

    def _index_call_args(self) -> dict[tuple[str, str], dict[str, Any]]:
        indexed = {}
        dataflow = self.semantics.get("dataflow") or {}
        for function, facts in (dataflow.get("functions") or {}).items():
            for call in facts.get("call_arguments", []):
                address = call.get("address")
                if address:
                    indexed[(function, address)] = call
        return indexed

    def _summary(self, functions: dict[str, Any], edges: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "function_count": len(functions),
            "operation_count": sum(len(item["flow"]) for item in functions.values()),
            "edge_count": len(edges),
            "functions_with_static_data": sum(
                1 for item in functions.values() if "uses_static_data" in item["tags"]
            ),
            "functions_with_type_activity": sum(
                1
                for item in functions.values()
                if any(
                    tag in item["tags"]
                    for tag in {
                        "reads_struct_fields",
                        "reads_go_string_fields",
                        "passes_slices",
                    }
                )
            ),
            "functions_with_transform_loops": sum(
                1 for item in functions.values() if "has_transform_loop" in item["tags"]
            ),
        }


def classify_runtime_call(target: str) -> tuple[str, str] | None:
    for prefix, kind in IMPORTANT_RUNTIME_CALLS.items():
        if target.startswith(prefix) or prefix in target:
            return kind
    return None


def is_noise_call(target: str) -> bool:
    return is_runtime_noise_call(target)


def has_interesting_args(args: dict[str, Any]) -> bool:
    return bool(
        args.get("string_args")
        or args.get("slice_args")
        or any(arg.get("kind") not in {"int", "call_return"} for arg in args.get("args", []))
    )


def compress_call_args(args: dict[str, Any]) -> dict[str, Any]:
    if not args:
        return {}
    result = {}
    if args.get("string_args"):
        result["strings"] = args["string_args"][:10]
    if args.get("slice_args"):
        result["slices"] = args["slice_args"][:10]
    symbolic = [
        arg
        for arg in args.get("args", [])
        if arg.get("kind") not in {"int", "call_return"}
    ]
    if symbolic:
        result["symbolic"] = symbolic[:12]
    return result
