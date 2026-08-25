from __future__ import annotations

import re
import shlex
from typing import Any

from gobbler.passes.http_args import typed_arguments


MAX_COMPONENTS = 12
MAX_PREVIEW = 240


def enrich_process_and_file_arguments(sink: dict[str, Any]) -> None:
    category = sink.get("category")
    if category == "process":
        process_args = process_arguments(sink)
        if process_args:
            sink["process_arguments"] = process_args
    elif category == "filesystem":
        file_args = file_arguments(sink)
        if file_args:
            sink["file_arguments"] = file_args


def process_arguments(sink: dict[str, Any]) -> dict[str, Any]:
    shape = process_shape(sink)
    if shape == "process_object_run":
        return {}
    values = ordered_strings(sink)
    executable = first_process_executable(sink, values)
    argv = process_argv(values, executable)
    array_argv = process_argv_from_argument_arrays(sink, executable)
    if array_argv:
        argv = append_argument_values(argv, array_argv, MAX_COMPONENTS)
    result: dict[str, Any] = {"api_shape": shape}
    if executable:
        result["executable"] = executable
    if argv:
        result["argv"] = argv[:MAX_COMPONENTS]
        result["command_line_preview"] = command_line_preview(executable, argv)
        if array_argv:
            result["argv_provenance"] = {
                "source": "argument_array_or_slice",
                "classification": "process_argument_components",
                "component_count": len(array_argv),
            }
    elif sink.get("data_sources"):
        result["argv_source"] = {
            "source": "related_static_data",
            "classification": "unknown_argv",
            "components": compact_components(sink.get("data_sources") or []),
        }
    return result if len(result) > 1 else {}


def file_arguments(sink: dict[str, Any]) -> dict[str, Any]:
    shape = file_shape(sink)
    values = ordered_strings(sink)
    path = first_path_value(sink, values)
    result: dict[str, Any] = {"api_shape": shape}
    if path:
        result["path"] = path
    if sink.get("kind") in {"file_write", "file_create"}:
        result["data"] = file_write_data(sink, values)
    if sink.get("kind") in {"file_read", "file_open", "stream_read"}:
        result["read_target"] = {
            "source": path.get("source") if path else "unresolved_argument",
            "classification": "path" if path else "unknown_read_target",
        }
        result["read_result"] = file_read_result(path)
    flags = file_flags(sink)
    if flags:
        result["flags"] = flags
    mode = file_mode(sink)
    if mode:
        result["mode"] = mode
    return result if len(result) > 1 else {}


def process_shape(sink: dict[str, Any]) -> str:
    target = str(sink.get("target") or sink.get("api") or "").lower()
    if "commandcontext" in target:
        return "exec_command_context"
    if "exec.command" in target or "os/exec.command" in target:
        return "exec_command"
    if "startprocess" in target:
        return "start_process"
    if "forkexec" in target:
        return "fork_exec"
    if "syscall.exec" in target or target.endswith("execve"):
        return "syscall_exec"
    if ".run" in target or ".start" in target:
        return "process_object_run"
    return "process_launch"


def file_shape(sink: dict[str, Any]) -> str:
    target = str(sink.get("target") or sink.get("api") or "").lower()
    kind = sink.get("kind")
    if "writefile" in target:
        return "write_file"
    if "readfile" in target:
        return "read_file"
    if "openfile" in target:
        return "open_file"
    if kind == "file_create":
        return "create_file"
    if kind == "file_open":
        return "open_file"
    if kind == "file_read":
        return "read_file"
    if kind == "file_write":
        return "write_file"
    return str(kind or "file_operation")


def ordered_strings(sink: dict[str, Any]) -> list[dict[str, Any]]:
    values = []
    for item in (sink.get("args") or {}).get("typed_string_args", []):
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            values.append(
                {
                    "value": item["value"],
                    "source": "dataflow",
                    "location": item.get("location"),
                }
            )
    for key, value in (sink.get("args") or {}).get("registers", {}).items():
        if isinstance(value, str):
            values.append({"value": value, "source": "call_graph", "location": key})
    for index, value in enumerate(sink.get("strings") or []):
        if isinstance(value, str):
            values.append({"value": value, "source": "sink_strings", "location": f"strings[{index}]"})
    return dedupe(values)


def first_process_executable(
    sink: dict[str, Any], values: list[dict[str, Any]]
) -> dict[str, Any] | None:
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") == "command":
            value = artifact.get("value")
            if isinstance(value, str) and useful_command_part(value):
                return argument_value(value, "artifact", None)
    for value in values:
        text = value["value"]
        if useful_command_part(text):
            return argument_value(text, value.get("source"), value.get("location"))
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") in {"command", "file_name", "path", "windows_path"}:
            value = artifact.get("value")
            if isinstance(value, str) and useful_command_part(value):
                return argument_value(value, "artifact", None)
    return None


def process_argv(
    values: list[dict[str, Any]], executable: dict[str, Any] | None
) -> list[dict[str, Any]]:
    result = []
    seen = set()
    executable_value = executable.get("value") if executable else None
    skipped_executable = False
    has_direct_arg_evidence = any(value.get("source") in {"dataflow", "call_graph"} for value in values)
    for value in values:
        text = value["value"]
        if has_direct_arg_evidence and value.get("source") == "sink_strings":
            continue
        if not useful_argv_part(text):
            continue
        if executable_value == text and not skipped_executable:
            skipped_executable = True
            continue
        if text in seen or text == executable_value:
            continue
        seen.add(text)
        result.append(argument_value(text, value.get("source"), value.get("location")))
    return result


def process_argv_from_argument_arrays(
    sink: dict[str, Any],
    executable: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    result = []
    executable_value = executable.get("value") if executable else None
    for component in argument_array_components(sink):
        text = component.get("value")
        if not isinstance(text, str) or not useful_argv_part(text):
            continue
        if text == executable_value:
            continue
        result.append(argument_value(text, component.get("source"), component.get("location")))
    return dedupe(result)


def argument_array_components(sink: dict[str, Any]) -> list[dict[str, Any]]:
    components = []
    args = sink.get("args") or {}
    for source_key in ("slices", "symbolic"):
        for index, item in enumerate(args.get(source_key) or []):
            if not isinstance(item, dict):
                continue
            components.extend(components_from_symbolic_argument(item, f"{source_key}[{index}]"))
    return dedupe(components)


def components_from_symbolic_argument(item: dict[str, Any], location: str) -> list[dict[str, Any]]:
    values = []
    value = item.get("value")
    if isinstance(value, str):
        values.extend(split_argument_preview(value))
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    values.extend(preview_components_from_source(source))
    return [
        {"value": value, "source": "argument_array_or_slice", "location": location}
        for value in values
    ]


def preview_components_from_source(source: dict[str, Any]) -> list[str]:
    values = []
    for key in ("text_preview", "preview"):
        value = source.get(key)
        if isinstance(value, str):
            values.extend(split_argument_preview(value))
    return unique_strings(values)


def split_argument_preview(value: str) -> list[str]:
    text = value.replace("\x00", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = " ".join(text.split())
    if not text or len(text) > 1000:
        return []
    try:
        parts = shlex.split(text, posix=False)
    except ValueError:
        parts = re.findall(r'"[^"]{1,240}"|\'[^\']{1,240}\'|\S{1,240}', text)
    return [part.strip("\"'") for part in parts if part.strip("\"'")]


def append_argument_values(
    existing: list[dict[str, Any]],
    extra: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    result = list(existing)
    seen = {item.get("value") for item in result}
    for item in extra:
        value = item.get("value")
        if value in seen:
            continue
        seen.add(value)
        result.append(item)
        if len(result) >= limit:
            break
    return result


def first_path_value(sink: dict[str, Any], values: list[dict[str, Any]]) -> dict[str, Any] | None:
    for artifact in sink.get("artifacts") or []:
        value = artifact.get("value")
        if artifact.get("type") == "windows_path":
            if isinstance(value, str) and path_argument_candidate(value):
                return argument_value(value, "artifact", None)
        if artifact.get("type") == "path":
            if isinstance(value, str) and path_argument_candidate(value):
                return argument_value(value, "artifact", None)
    for value in values:
        text = value["value"]
        if path_argument_candidate(text):
            return argument_value(text, value.get("source"), value.get("location"))
    for artifact in sink.get("artifacts") or []:
        if artifact.get("type") == "file_name":
            value = artifact.get("value")
            if isinstance(value, str) and not command_like_filename(value):
                return argument_value(value, "artifact", None)
    return None


def file_write_data(sink: dict[str, Any], values: list[dict[str, Any]]) -> dict[str, Any]:
    for value in values:
        text = value["value"]
        if looks_like_path(text):
            continue
        if useful_file_data_literal(text):
            return {
                "source": value.get("source") or "recovered_argument",
                "classification": classify_data_preview(text),
                "preview": preview(text),
            }
    slice_candidate = data_candidate_from_argument_arrays(sink)
    if slice_candidate:
        return slice_candidate
    sources = sink.get("data_sources") or []
    data_candidate = data_candidate_from_sources(sources)
    if data_candidate:
        return data_candidate
    if sources:
        return {
            "source": "related_static_data",
            "classification": "unknown_write_data",
            "components": compact_components(sources),
        }
    return {
        "source": "unresolved_argument",
        "classification": "unknown_write_data",
    }


def file_read_result(path: dict[str, Any] | None) -> dict[str, Any]:
    result = {
        "source": "filesystem_runtime",
        "classification": "file_contents",
    }
    if path and path.get("value"):
        result["path"] = path.get("value")
    return result


def file_mode(sink: dict[str, Any]) -> dict[str, Any] | None:
    ints = integer_arguments(sink)
    if not ints:
        return None
    candidates = ints[1:] if file_shape(sink) == "open_file" and len(ints) > 1 else ints
    for arg in candidates:
        value = arg.get("value")
        if not isinstance(value, int):
            continue
        if value in {0, 0o600, 0o644, 0o666, 0o755, 0o777}:
            return {"value": oct(value), "source": "typed_integer_argument"}
    return None


def file_flags(sink: dict[str, Any]) -> dict[str, Any] | None:
    if file_shape(sink) != "open_file":
        return None
    ints = integer_arguments(sink)
    if not ints:
        return None
    value = ints[0].get("value")
    if not isinstance(value, int):
        return None
    decoded = decode_open_flags(value)
    return {
        "value": value,
        "hex": hex(value),
        "decoded": decoded,
        "source": "typed_integer_argument",
    }


def integer_arguments(sink: dict[str, Any]) -> list[dict[str, Any]]:
    values = []
    for arg in typed_arguments(sink):
        if arg.get("kind") != "int":
            continue
        value = arg.get("value")
        if not isinstance(value, int):
            continue
        values.append(arg)
    return values


def decode_open_flags(value: int) -> list[str]:
    names = []
    access = value & 0x3
    if access == 0:
        names.append("O_RDONLY")
    elif access == 1:
        names.append("O_WRONLY")
    elif access == 2:
        names.append("O_RDWR")
    flags = (
        (0x40, "O_CREAT"),
        (0x200, "O_TRUNC"),
        (0x400, "O_APPEND"),
        (0x800, "O_NONBLOCK"),
        (0x1000, "O_SYNC"),
        (0x80, "O_EXCL"),
    )
    for mask, name in flags:
        if value & mask:
            names.append(name)
    return names


def data_candidate_from_sources(sources: list[Any]) -> dict[str, Any] | None:
    for source in sources:
        if not isinstance(source, dict):
            continue
        magic_names = [
            item.get("magic")
            for item in source.get("magic_offsets") or []
            if isinstance(item, dict) and item.get("magic")
        ]
        if magic_names:
            return {
                "source": "related_static_data",
                "classification": classify_magic_data(magic_names),
                "size": source.get("size"),
                "magic": magic_names[:6],
                "source_kind": source.get("kind"),
            }
        for key in ("text_preview", "preview"):
            value = source.get(key)
            if not isinstance(value, str):
                continue
            candidate = extract_data_candidate(value)
            if candidate:
                return {
                    "source": "nearby_static_data_candidate",
                    "classification": classify_data_preview(candidate),
                    "preview": preview(candidate),
                    "source_kind": source.get("kind"),
                }
    return None


def classify_magic_data(magic_names: list[str]) -> str:
    names = {str(name).upper() for name in magic_names}
    if names & {"MZ", "PE", "ELF"}:
        return "executable_or_object_data"
    if names & {"PK", "GZIP", "ZLIB"}:
        return "archive_or_compressed_data"
    return "static_binary_data"


def data_candidate_from_argument_arrays(sink: dict[str, Any]) -> dict[str, Any] | None:
    candidates = []
    args = sink.get("args") or {}
    for source_key in ("slices", "symbolic"):
        for item in args.get(source_key) or []:
            if not isinstance(item, dict):
                continue
            source = item.get("source") if isinstance(item.get("source"), dict) else {}
            candidate = data_candidate_from_symbolic_argument(item, source_key, source)
            if candidate:
                candidates.append(candidate)
    return candidates[0] if candidates else None


def data_candidate_from_symbolic_argument(
    item: dict[str, Any],
    source_key: str,
    source: dict[str, Any],
) -> dict[str, Any] | None:
    previews = []
    if isinstance(item.get("value"), str):
        previews.append(item["value"])
    for key in ("text_preview", "preview"):
        value = source.get(key)
        if isinstance(value, str):
            previews.append(value)

    for text in previews:
        candidate = extract_data_candidate(text) or (text if useful_file_data_literal(text) else None)
        if not candidate:
            continue
        result = {
            "source": "argument_array_or_slice",
            "classification": classify_data_preview(candidate),
            "preview": preview(candidate),
            "source_kind": source.get("kind") or item.get("kind") or source_key,
        }
        size = item.get("length") or source.get("size")
        if size:
            result["size"] = size
        return result

    if source:
        result = {
            "source": "argument_array_or_slice",
            "classification": "byte_slice_or_buffer",
            "source_kind": source.get("kind") or item.get("kind") or source_key,
            "components": compact_components([source]),
        }
        size = item.get("length") or source.get("size")
        if size:
            result["size"] = size
        return result
    return None


def extract_data_candidate(value: str) -> str | None:
    json_match = re.search(r"(\{[^{}]{2,240}\})", value)
    if json_match and looks_like_structured_json(json_match.group(1)):
        return json_match.group(1)
    script_match = re.search(r"(?i)((?:#![^\n]+|powershell\s+-|cmd\.exe\s+/|/bin/(?:sh|bash)\s+-).{0,240})", value)
    if script_match:
        return script_match.group(1)
    assignment = re.search(r"\b[A-Za-z_][A-Za-z0-9_]{1,40}=[^\s]{1,180}", value)
    if assignment:
        return assignment.group(0)
    return None


def useful_command_part(value: str) -> bool:
    if not value or len(value) > 500:
        return False
    if "\x00" in value or "\n" in value:
        return False
    if runtime_string_table_fragment(value):
        return False
    if len(value) > 40 and not re.search(r"[\s\"']", value) and not value.startswith(("-", "/")):
        return False
    if looks_like_url(value):
        return False
    if looks_like_path(value):
        return True
    if value.startswith("-") or value.startswith("/"):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.:\\/-]{1,160}", value))


def useful_argv_part(value: str) -> bool:
    if not useful_command_part(value):
        return False
    if value.endswith("."):
        return False
    if value.startswith(("-", "/")):
        return True
    if looks_like_path(value):
        return True
    if re.fullmatch(r"[a-z0-9_.-]{1,80}", value):
        return True
    if re.fullmatch(r"[A-Z_]{2,80}", value):
        return True
    return False


def useful_file_data_literal(value: str) -> bool:
    if not value or len(value) > 2000:
        return False
    if looks_like_path(value) or looks_like_url(value):
        return False
    if len(value) >= 12 and any(ch in value for ch in "{}[]= \t"):
        return True
    return False


def looks_like_path(value: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
        return True
    if value.startswith(("/", "./", "../")):
        return True
    if "\\" in value:
        return True
    if "/" in value and not looks_like_url(value):
        return True
    return bool(re.search(r"\.[A-Za-z0-9]{1,8}$", value))


def path_argument_candidate(value: str) -> bool:
    if not value or len(value) > 500:
        return False
    if command_like_filename(value):
        return False
    if runtime_string_table_fragment(value):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
        return True
    if value.startswith(("/", "./", "../")):
        return not looks_like_url(value)
    if "/" in value and not looks_like_url(value) and not re.search(r"\s", value):
        return True
    if "\\" in value:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_. -]{1,160}\.[A-Za-z0-9]{1,8}", value))


def command_like_filename(value: str) -> bool:
    return value.lower() in {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "sh",
        "bash",
        "zsh",
        "whoami",
        "uname",
    }


def runtime_string_table_fragment(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "forcegc",
            "gctrace",
            "cpuprof",
            "allocm",
            "pathext",
            "trap console",
            "file too large",
            "is a directory",
            "illegal instruction",
            "waitforsingleobject",
            "regenumvalue",
        )
    )


def looks_like_url(value: str) -> bool:
    return bool(re.match(r"https?://", value))


def classify_data_preview(value: str) -> str:
    text = value.strip()
    if text.startswith("{") or text.startswith("["):
        return "json_like"
    if text.startswith("#!") or "powershell" in text.lower() or "cmd.exe" in text.lower():
        return "script_or_command_like"
    if "=" in text:
        return "key_value_like"
    return "literal_string"


def looks_like_structured_json(value: str) -> bool:
    text = value.strip()
    if text.startswith("{"):
        return ":" in text and '"' in text
    return False


def argument_value(value: str, source: str | None, location: str | None) -> dict[str, Any]:
    result = {"value": value, "source": source or "recovered_argument"}
    if location:
        result["location"] = location
    return result


def command_line_preview(executable: dict[str, Any] | None, argv: list[dict[str, Any]]) -> str | None:
    parts = []
    if executable and executable.get("value"):
        parts.append(str(executable["value"]))
    parts.extend(str(item["value"]) for item in argv if item.get("value"))
    return preview(" ".join(parts)) if parts else None


def compact_components(values: list[Any]) -> list[Any]:
    components = []
    for value in values[:MAX_COMPONENTS]:
        if isinstance(value, dict):
            compact = {
                key: value.get(key)
                for key in ("kind", "size", "entropy", "preview", "text_preview", "source")
                if value.get(key) not in (None, "", [], {})
            }
            if compact:
                components.append(compact)
        elif isinstance(value, str):
            components.append(preview(value))
    return components


def dedupe(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for value in values:
        key = (value.get("location"), value.get("value"))
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def unique_strings(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def preview(value: str) -> str:
    value = " ".join(value.split())
    if len(value) > MAX_PREVIEW:
        return value[:MAX_PREVIEW] + "...<truncated>"
    return value
