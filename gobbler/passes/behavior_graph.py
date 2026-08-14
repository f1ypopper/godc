from typing import Any


API_BEHAVIOR_HINTS = {
    "os.ReadFile": ("file_read", "filesystem"),
    "os.WriteFile": ("file_write", "filesystem"),
    "os.Open": ("file_open", "filesystem"),
    "os.OpenFile": ("file_open", "filesystem"),
    "os.Create": ("file_create", "filesystem"),
    "os.Remove": ("file_delete", "filesystem"),
    "os.Rename": ("file_rename", "filesystem"),
    "os.Mkdir": ("directory_create", "filesystem"),
    "os.Chmod": ("permission_change", "filesystem"),
    "os.Getenv": ("environment_read", "environment"),
    "os.Setenv": ("environment_write", "environment"),
    "path/filepath.Walk": ("recursive_filesystem_walk", "filesystem"),
    "path/filepath.WalkDir": ("recursive_filesystem_walk", "filesystem"),
    "io/ioutil.ReadFile": ("file_read", "filesystem"),
    "io/ioutil.WriteFile": ("file_write", "filesystem"),
    "io.ReadAll": ("stream_read", "io"),
    "net.Dial": ("network_connect", "network"),
    "net.Listen": ("network_listen", "network"),
    "net/http": ("http_network", "network"),
    "http.NewRequest": ("http_request", "network"),
    "http.Get": ("http_get", "network"),
    "http.Post": ("http_post", "network"),
    "os/exec.Command": ("process_launch", "process"),
    "exec.Command": ("process_launch", "process"),
    "syscall.LoadLibrary": ("dynamic_library_load", "loader"),
    "syscall.GetProcAddress": ("dynamic_import_resolution", "loader"),
    "syscall.Syscall": ("raw_syscall", "execution"),
    "syscall.SyscallN": ("raw_syscall", "execution"),
    "syscall.(*LazyProc).Call": ("dynamic_syscall_call", "execution"),
    "crypto/aes": ("aes_crypto", "crypto"),
    "crypto/cipher": ("cipher_crypto", "crypto"),
    "crypto/rand": ("crypto_random", "crypto"),
    "chacha20": ("chacha20_crypto", "crypto"),
    "github.com/ecies": ("ecies_crypto", "crypto"),
    "encoding/base64": ("base64_decode_or_encode", "encoding"),
    "encoding/hex": ("hex_decode_or_encode", "encoding"),
    "compress/gzip": ("gzip_compression", "compression"),
    "compress/zlib": ("zlib_compression", "compression"),
}


INTERESTING_STRING_CLASSES = {
    "url",
    "path_or_url_fragment",
    "dll_name",
    "environment_variable",
    "long_text",
}


def build_behavior_graph(graph: dict[str, list[Any]], semantics: dict[str, Any]) -> dict[str, Any]:
    builder = BehaviorGraphBuilder(graph, semantics)
    return builder.build()


class BehaviorGraphBuilder:
    def __init__(self, graph: dict[str, list[Any]], semantics: dict[str, Any]):
        self.graph = graph
        self.semantics = semantics
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.edge_keys: set[tuple[str, str, str, str | None]] = set()

    def build(self) -> dict[str, Any]:
        self._add_call_behavior()
        self._add_constants()
        self._add_suspicious_blobs()
        self._add_dataflow()
        self._add_cfg()
        self._add_transformers()
        self._add_loader_behaviors()
        self._add_embedded_payloads()
        self._add_indirect_calls()
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "summary": self._summary(),
        }

    def _add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "tags": sorted(set(tags or [])),
                "metadata": metadata or {},
            }
            return
        existing["tags"] = sorted(set(existing.get("tags", [])) | set(tags or []))
        existing["metadata"].update(metadata or {})

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        evidence: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        key = (source, target, edge_type, evidence)
        if key in self.edge_keys:
            return
        self.edge_keys.add(key)
        self.edges.append(
            {
                "from": source,
                "to": target,
                "type": edge_type,
                "evidence": evidence,
                "metadata": metadata or {},
            }
        )

    def _function_node(self, function: str, tags: list[str] | None = None) -> str:
        node_id = f"func:{function}"
        self._add_node(node_id, "function", function, tags or [])
        return node_id

    def _add_call_behavior(self) -> None:
        for function, calls in self.graph.items():
            function_id = self._function_node(function)
            for call in calls:
                if not getattr(call, "visible", True):
                    continue
                behavior = classify_call_behavior(call.target)
                if behavior is None:
                    if call.kind == "user" and call.target in self.graph:
                        callee_id = self._function_node(call.target)
                        self._add_edge(function_id, callee_id, "calls", hex(call.address))
                    continue
                action, category = behavior
                api_id = f"api:{action}:{call.target}"
                self._add_node(
                    api_id,
                    "api",
                    call.target,
                    [category, action],
                    {"address": hex(call.address), "category": category},
                )
                self._add_edge(
                    function_id,
                    api_id,
                    "invokes_behavior",
                    hex(call.address),
                    {"behavior": action, "category": category},
                )
                if call.string_args:
                    for index, value in enumerate(call.string_args):
                        string_id = f"literal_arg:{function}:{call.address:x}:{index}"
                        self._add_node(
                            string_id,
                            "string",
                            shorten(value),
                            ["argument_string", classify_inline_string(value)],
                            {"value": value},
                        )
                        self._add_edge(string_id, api_id, "argument_to", hex(call.address))

    def _add_constants(self) -> None:
        constants = self.semantics.get("global_constants") or {}
        for array in constants.get("constant_arrays") or []:
            tags = ["constant_array"]
            if "large_copy_source" in array.get("reasons", []):
                tags.append("large_copy_source")
            if array.get("entropy", 0) >= 7.2:
                tags.append("high_entropy")
            if array.get("magic_offsets"):
                tags.append("contains_magic")
            array_id = f"array:{array['id']}"
            self._add_node(
                array_id,
                "constant_array",
                f"{array['section']}:{array['va']}",
                tags,
                array,
            )
            for function in array.get("referenced_by", []):
                function_id = self._function_node(function)
                self._add_edge(array_id, function_id, "referenced_by")

        for string in constants.get("global_strings") or []:
            classification = string.get("classification", "string")
            if classification not in INTERESTING_STRING_CLASSES:
                continue
            string_id = f"string:{string['address']}"
            self._add_node(
                string_id,
                "string",
                shorten(string["value"]),
                [classification],
                string,
            )
            for function in string.get("referenced_by", []):
                function_id = self._function_node(function)
                self._add_edge(string_id, function_id, "referenced_by")

    def _add_suspicious_blobs(self) -> None:
        for blob in self.semantics.get("suspicious_data_blobs") or []:
            blob_id = f"blob:{blob['id']}"
            tags = ["suspicious_data_blob"] + blob.get("reasons", [])
            self._add_node(
                blob_id,
                "data_blob",
                f"{blob['section']}:{blob['va']}",
                tags,
                blob,
            )
            for function in blob.get("referenced_by", []):
                function_id = self._function_node(function)
                self._add_edge(blob_id, function_id, "referenced_by")
            array_id = self._array_for_blob(blob)
            if array_id:
                self._add_edge(array_id, blob_id, "overlaps")

    def _add_transformers(self) -> None:
        for transformer in self.semantics.get("data_transformers") or []:
            function_id = self._function_node(
                transformer["function"],
                ["data_transformer", f"confidence:{transformer['confidence']}"],
            )
            for source in transformer.get("input_sources", []):
                blob_id = f"blob:{source}"
                if blob_id in self.nodes:
                    self._add_edge(blob_id, function_id, "input_to_transformer")
            for copy in transformer.get("large_copies", []):
                self._add_edge(
                    function_id,
                    self._copy_node(copy),
                    "performs_large_copy",
                    copy.get("instruction"),
                    copy,
                )

    def _add_dataflow(self) -> None:
        dataflow = self.semantics.get("dataflow") or {}
        for function, facts in (dataflow.get("functions") or {}).items():
            function_id = self._function_node(function, ["has_dataflow"])
            for flow in facts.get("value_flows", []):
                source_id = self._node_for_flow_source(flow)
                if source_id is None:
                    continue
                target_id = self._function_node(flow["to"])
                self._add_edge(
                    source_id,
                    target_id,
                    "flows_to_call",
                    flow.get("address"),
                    flow,
                )
            for call in facts.get("call_arguments", [])[:50]:
                call_id = f"typed_call:{function}:{call['address']}:{call['target']}"
                self._add_node(
                    call_id,
                    "typed_call",
                    call["target"],
                    ["typed_arguments"],
                    call,
                )
                self._add_edge(function_id, call_id, "has_typed_call", call["address"])
            for field in facts.get("struct_field_accesses", [])[:50]:
                field_id = (
                    f"struct_field:{function}:{field['instruction']}:"
                    f"{field['base_reg']}:{field['field_offset']}"
                )
                self._add_node(
                    field_id,
                    "struct_field",
                    f"{field['base_reg']}+{field['field_offset']}",
                    ["struct_field_access"],
                    field,
                )
                self._add_edge(function_id, field_id, "reads_struct_field", field["instruction"])
            for candidate in facts.get("string_field_candidates", [])[:20]:
                candidate_id = (
                    f"struct_string:{function}:{candidate['base_reg']}:"
                    f"{candidate['pointer_offset']}:{candidate['length_offset']}"
                )
                self._add_node(
                    candidate_id,
                    "struct_string_candidate",
                    f"{candidate['base_reg']} string field",
                    ["go_string_field_candidate"],
                    candidate,
                )
                self._add_edge(function_id, candidate_id, "may_read_string_field", candidate["instruction"])

    def _node_for_flow_source(self, flow: dict[str, Any]) -> str | None:
        kind = flow.get("from_kind")
        label = flow.get("from")
        if kind == "constant_array":
            node_id = f"array:{label}"
            return node_id if node_id in self.nodes else None
        if kind == "data_blob":
            node_id = f"blob:{label}"
            return node_id if node_id in self.nodes else None
        if kind == "global_string":
            node_id = f"flow_string:{label}"
            self._add_node(node_id, "string", shorten(str(label)), ["global_string"])
            return node_id
        return None

    def _add_cfg(self) -> None:
        cfg = self.semantics.get("cfg") or {}
        for function, facts in (cfg.get("functions") or {}).items():
            function_id = self._function_node(function, ["has_cfg"])
            for loop in facts.get("probable_transform_loops", []):
                loop_id = f"loop:{function}:{loop['start']}:{loop['end']}"
                tags = ["probable_transform_loop"] + [
                    f"op:{op}" for op in loop.get("evidence", {}).get("transform_ops", [])
                ]
                self._add_node(
                    loop_id,
                    "loop",
                    f"{function} {loop['start']}-{loop['end']}",
                    tags,
                    loop,
                )
                self._add_edge(function_id, loop_id, "contains_transform_loop")

    def _copy_node(self, copy: dict[str, Any]) -> str:
        node_id = f"copy:{copy.get('instruction')}:{copy.get('source')}"
        self._add_node(
            node_id,
            "operation",
            f"large copy {copy.get('size')}",
            ["large_copy"],
            copy,
        )
        return node_id

    def _add_loader_behaviors(self) -> None:
        for loader in self.semantics.get("loader_behaviors") or []:
            loader_id = f"loader:{loader['function']}:{loader['kind']}"
            self._add_node(
                loader_id,
                "behavior",
                loader["kind"],
                ["loader", loader["kind"], f"confidence:{loader['confidence']}"],
                loader,
            )
            if loader["function"] != "<reachable_component>":
                function_id = self._function_node(loader["function"], ["loader_participant"])
                self._add_edge(function_id, loader_id, "has_behavior")
            for function in loader.get("functions", []):
                function_id = self._function_node(function, ["loader_participant"])
                self._add_edge(function_id, loader_id, "contributes_to")
            for transformer in loader.get("called_transformers", []):
                transformer_id = self._function_node(transformer, ["data_transformer"])
                self._add_edge(transformer_id, loader_id, "feeds_loader")

    def _add_embedded_payloads(self) -> None:
        for index, payload in enumerate(self.semantics.get("embedded_payloads") or []):
            payload_id = f"payload:{index}"
            self._add_node(
                payload_id,
                "artifact",
                payload["kind"],
                ["embedded_payload", f"confidence:{payload['confidence']}"],
                payload,
            )
            source_blob = payload.get("source_blob")
            if source_blob:
                blob_id = f"blob:{source_blob}"
                if blob_id in self.nodes:
                    self._add_edge(blob_id, payload_id, "source_for_payload")
            for transformer in payload.get("transformers", []):
                transformer_id = self._function_node(transformer, ["data_transformer"])
                self._add_edge(transformer_id, payload_id, "transforms_into")
            for loader in payload.get("loaders", []):
                loader_targets = [
                    node_id
                    for node_id, node in self.nodes.items()
                    if node["type"] == "behavior"
                    and node["metadata"].get("function") == loader
                ]
                for loader_id in loader_targets:
                    self._add_edge(payload_id, loader_id, "loaded_or_executed_by")

    def _add_indirect_calls(self) -> None:
        for call in self.semantics.get("indirect_calls") or []:
            if call["classification"] == "unresolved_indirect_call":
                continue
            function_id = self._function_node(function=call["function"])
            call_id = f"indirect:{call['function']}:{call['address']}"
            self._add_node(
                call_id,
                "indirect_call",
                call["operand"],
                [call["classification"], call["kind"]],
                call,
            )
            self._add_edge(function_id, call_id, "performs_indirect_call", call["address"])

    def _array_for_blob(self, blob: dict[str, Any]) -> str | None:
        blob_start = int(blob["va"], 16)
        blob_end = blob_start + int(blob["size"], 16)
        constants = self.semantics.get("global_constants") or {}
        for array in constants.get("constant_arrays") or []:
            if array["section"] != blob["section"]:
                continue
            array_start = int(array["va"], 16)
            array_end = array_start + int(array["size"], 16)
            if array_start < blob_end and blob_start < array_end:
                return f"array:{array['id']}"
        return None

    def _summary(self) -> dict[str, Any]:
        node_counts: dict[str, int] = {}
        edge_counts: dict[str, int] = {}
        for node in self.nodes.values():
            node_counts[node["type"]] = node_counts.get(node["type"], 0) + 1
        for edge in self.edges:
            edge_counts[edge["type"]] = edge_counts.get(edge["type"], 0) + 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_counts": node_counts,
            "edge_counts": edge_counts,
        }


def classify_call_behavior(target: str) -> tuple[str, str] | None:
    for needle, behavior in API_BEHAVIOR_HINTS.items():
        if needle in target:
            return behavior
    return None


def classify_inline_string(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "\\" in value or "/" in value:
        return "path_or_url_fragment"
    if lowered.endswith(".dll"):
        return "dll_name"
    if len(value) > 120:
        return "long_text"
    return "string"


def shorten(value: str, limit: int = 96) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
