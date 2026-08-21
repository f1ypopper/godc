"""Go type and package metadata extraction.

This pass intentionally depends only on the loose shape of GoReSym output.
Different GoReSym builds expose type metadata with different field names, and
some builds leave the top-level Types/Interfaces entries empty.  The fallback is
to recover package and receiver-type hints from function symbols.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any


MAX_PACKAGES = 200
MAX_TYPE_NAMES = 500
MAX_INTERESTING_TYPES = 100
MAX_STRUCT_TYPES = 100
MAX_INTERFACE_TYPES = 100
MAX_METHODS = 20
MAX_FIELDS = 40
MAX_SOURCES = 8
MAX_NOTES = 12
MAX_RECURSION_DEPTH = 4


INTERESTING_TERMS = (
    "aes",
    "archive",
    "auth",
    "beacon",
    "bot",
    "cert",
    "cipher",
    "cmd",
    "command",
    "config",
    "cookie",
    "credential",
    "crypto",
    "decrypt",
    "discord",
    "domain",
    "encrypt",
    "exec",
    "file",
    "gzip",
    "host",
    "http",
    "inject",
    "key",
    "loader",
    "mutex",
    "password",
    "path",
    "payload",
    "persist",
    "process",
    "proxy",
    "registry",
    "request",
    "response",
    "secret",
    "service",
    "shell",
    "task",
    "telegram",
    "tls",
    "token",
    "url",
    "wallet",
    "xor",
    "zip",
)

NOISY_PACKAGE_PREFIXES = (
    "runtime",
    "internal/",
    "internal.",
    "sync",
    "syscall",
    "reflect",
    "unsafe",
    "errors",
    "fmt",
    "io",
    "os",
    "path",
    "strings",
    "strconv",
    "slices",
    "sort",
    "unicode",
)


def analyze_go_types(analyzer: Any) -> dict[str, Any]:
    """Extract compact Go package/type metadata from an analyzer instance.

    The function accepts the current Gobbler Analyzer, but only requires an
    object with a ``goresym`` dict.  Missing fields are tolerated and recorded in
    the summary notes instead of raising.
    """

    goresym = getattr(analyzer, "goresym", None)
    if not isinstance(goresym, dict):
        return {
            "summary": {
                "available": False,
                "reason": "analyzer.goresym is missing or not a dict",
            },
            "packages": [],
            "type_names": [],
            "interesting_types": [],
            "struct_like_types": [],
            "interface_like_types": [],
        }

    extractor = GoTypeExtractor(analyzer, goresym)
    return extractor.extract()


class GoTypeExtractor:
    def __init__(self, analyzer: Any, goresym: dict[str, Any]):
        self.analyzer = analyzer
        self.goresym = goresym
        self.notes: list[str] = []
        self.package_stats: dict[str, dict[str, Any]] = {}
        self.type_items_by_name: dict[str, dict[str, Any]] = {}
        self.struct_like: dict[str, dict[str, Any]] = {}
        self.interface_like: dict[str, dict[str, Any]] = {}
        self.interesting: dict[str, dict[str, Any]] = {}

    def extract(self) -> dict[str, Any]:
        self._extract_build_packages()
        self._extract_types_from_goresym()
        self._extract_interfaces_from_goresym()
        self._extract_symbol_metadata()

        packages = self._final_packages()
        type_names = sorted(self.type_items_by_name)[:MAX_TYPE_NAMES]
        interesting_types = self._ranked(self.interesting, MAX_INTERESTING_TYPES)
        struct_like_types = self._ranked(self.struct_like, MAX_STRUCT_TYPES)
        interface_like_types = self._ranked(self.interface_like, MAX_INTERFACE_TYPES)

        declared_types = _as_list(self.goresym.get("Types"))
        declared_interfaces = _as_list(self.goresym.get("Interfaces"))
        extraction_sources = []
        if declared_types:
            extraction_sources.append("goresym.Types")
        if declared_interfaces:
            extraction_sources.append("goresym.Interfaces")
        if self._functions():
            extraction_sources.append("function_symbols")
        if self._build_info():
            extraction_sources.append("build_info")

        if not declared_types:
            self._note("goresym.Types is empty or unavailable; receiver/function symbols were used as fallback")
        if not declared_interfaces:
            self._note("goresym.Interfaces is empty or unavailable")

        return {
            "summary": {
                "available": True,
                "go_version": _safe_str(self.goresym.get("Version"))
                or _safe_str(self._build_info().get("GoVersion")),
                "module_path": self._module_path(),
                "goos": _safe_str(self.goresym.get("OS")),
                "goarch": _safe_str(self.goresym.get("Arch")),
                "available_goresym_keys": sorted(self.goresym.keys()),
                "extraction_sources": extraction_sources,
                "package_count": len(self.package_stats),
                "type_name_count": len(self.type_items_by_name),
                "declared_type_record_count": len(declared_types),
                "declared_interface_record_count": len(declared_interfaces),
                "struct_like_type_count": len(self.struct_like),
                "interface_like_type_count": len(self.interface_like),
                "interesting_type_count": len(self.interesting),
                "notes": self.notes[:MAX_NOTES],
            },
            "packages": packages,
            "type_names": type_names,
            "interesting_types": interesting_types,
            "struct_like_types": struct_like_types,
            "interface_like_types": interface_like_types,
        }

    def _extract_build_packages(self) -> None:
        build_info = self._build_info()
        module_path = self._module_path()
        if module_path:
            self._package(module_path, "build_info.main")

        main = build_info.get("Main")
        if isinstance(main, dict):
            path = _safe_str(main.get("Path"))
            if path:
                self._package(path, "build_info.main")

        deps = _as_list(build_info.get("Deps"))
        for dep in deps:
            path = _path_from_build_dep(dep)
            if path:
                self._package(path, "build_info.dep")

    def _extract_types_from_goresym(self) -> None:
        for record in _as_list(self.goresym.get("Types")):
            for item in self._type_records(record):
                self._record_type(item)

    def _extract_interfaces_from_goresym(self) -> None:
        for record in _as_list(self.goresym.get("Interfaces")):
            item = self._normalize_type_record(record, source="goresym.Interfaces")
            if item["name"]:
                item["kind"] = item["kind"] or "interface"
                self._record_type(item, force_interface=True)

    def _extract_symbol_metadata(self) -> None:
        for function in self._functions():
            name = _safe_str(function.get("FullName") or function.get("Name"))
            if not name:
                continue
            package = _package_from_function(name)
            if package:
                stats = self._package(package, "function_symbols")
                stats["function_count"] += 1

            receiver = _receiver_type_from_function(name)
            if receiver:
                receiver_package = receiver.get("package") or package
                type_name = receiver["name"]
                qualified_name = _qualified_name(receiver_package, type_name)
                item = self.type_items_by_name.setdefault(
                    qualified_name,
                    {
                        "name": qualified_name,
                        "short_name": type_name,
                        "package": receiver_package,
                        "kind": "receiver_type",
                        "source": "function_symbols",
                        "field_names": [],
                        "method_names": [],
                        "evidence": [],
                        "score": 0,
                    },
                )
                _append_unique(item["method_names"], _method_name_from_function(name), MAX_METHODS)
                _append_unique(item["evidence"], "method receiver recovered from function symbol", MAX_SOURCES)
                item["score"] += 1
                if receiver_package:
                    self._package(receiver_package, "function_symbols")["type_names"].add(qualified_name)
                self._maybe_mark_interesting(item)

    def _type_records(self, value: Any, depth: int = 0) -> list[dict[str, Any]]:
        if depth > MAX_RECURSION_DEPTH:
            return []
        if isinstance(value, list):
            items = []
            for entry in value:
                items.extend(self._type_records(entry, depth + 1))
            return items
        if not isinstance(value, dict):
            return []

        own = self._normalize_type_record(value, source="goresym.Types")
        records = [own] if own["name"] else []

        for key in ("Types", "TypeList", "TypeLinks", "Nested", "Children", "Elements"):
            nested = value.get(key)
            if isinstance(nested, (list, dict)):
                records.extend(self._type_records(nested, depth + 1))
        return records

    def _normalize_type_record(self, record: Any, source: str) -> dict[str, Any]:
        if not isinstance(record, dict):
            return _empty_type_item(source)

        raw_name = _first_str(
            record,
            "Name",
            "FullName",
            "Str",
            "String",
            "TypeName",
            "Type",
        )
        package = _first_str(record, "PkgPath", "Package", "PackagePath", "Pkg", "PkgName")
        short_name = _short_type_name(raw_name)
        if not package:
            package = _package_from_type_name(raw_name)
        name = _qualified_name(package, short_name) if short_name else _safe_str(raw_name)

        kind = _first_str(record, "Kind", "KindString", "Category")
        if not kind:
            kind = _infer_kind(record)

        field_names = _names_from_records(
            record.get("Fields")
            or record.get("Field")
            or record.get("StructFields")
            or record.get("fields"),
            MAX_FIELDS,
        )
        method_names = _names_from_records(
            record.get("Methods")
            or record.get("Method")
            or record.get("Imethods")
            or record.get("methods"),
            MAX_METHODS,
        )

        evidence = [source]
        if field_names:
            evidence.append("field metadata present")
        if method_names:
            evidence.append("method metadata present")

        return {
            "name": name,
            "short_name": short_name or name,
            "package": package,
            "kind": kind,
            "source": source,
            "field_names": field_names,
            "method_names": method_names,
            "evidence": evidence,
            "score": 0,
        }

    def _record_type(self, item: dict[str, Any], force_interface: bool = False) -> None:
        name = item.get("name")
        if not name:
            return
        existing = self.type_items_by_name.get(name)
        if existing is None:
            self.type_items_by_name[name] = item
            existing = item
        else:
            self._merge_type(existing, item)

        package = _safe_str(existing.get("package"))
        if package:
            self._package(package, existing.get("source") or "goresym.Types")["type_names"].add(name)

        kind = _safe_str(existing.get("kind")).lower()
        if force_interface or "interface" in kind:
            self.interface_like[name] = existing
        elif "struct" in kind or existing.get("field_names"):
            self.struct_like[name] = existing

        self._maybe_mark_interesting(existing)

    def _merge_type(self, dst: dict[str, Any], src: dict[str, Any]) -> None:
        for key in ("kind", "package", "short_name"):
            if not dst.get(key) and src.get(key):
                dst[key] = src[key]
        for key in ("field_names", "method_names", "evidence"):
            for value in src.get(key) or []:
                limit = MAX_FIELDS if key == "field_names" else MAX_METHODS
                if key == "evidence":
                    limit = MAX_SOURCES
                _append_unique(dst.setdefault(key, []), value, limit)
        dst["score"] = int(dst.get("score") or 0) + int(src.get("score") or 0)

    def _maybe_mark_interesting(self, item: dict[str, Any]) -> None:
        haystack = " ".join(
            _safe_str(part)
            for part in (
                item.get("name"),
                item.get("package"),
                " ".join(item.get("field_names") or []),
                " ".join(item.get("method_names") or []),
            )
        ).lower()
        matched = [term for term in INTERESTING_TERMS if term in haystack]
        if not matched:
            return
        item = dict(item)
        item["matched_terms"] = matched[:12]
        item["score"] = int(item.get("score") or 0) + len(matched) * 10
        self.interesting[item["name"]] = item

    def _final_packages(self) -> list[dict[str, Any]]:
        packages = []
        for path, stats in self.package_stats.items():
            item = {
                "path": path,
                "kind": _package_kind(path, self._module_path()),
                "source": sorted(stats["sources"]),
                "function_count": stats["function_count"],
                "type_count": len(stats["type_names"]),
                "interesting_terms": _matched_terms(path),
            }
            packages.append(item)
        packages.sort(
            key=lambda item: (
                not bool(item["interesting_terms"]),
                -item["type_count"],
                -item["function_count"],
                item["path"],
            )
        )
        return packages[:MAX_PACKAGES]

    def _ranked(self, items: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        ranked = []
        for item in items.values():
            compact = {
                "name": item.get("name"),
                "short_name": item.get("short_name"),
                "package": item.get("package"),
                "kind": item.get("kind"),
                "source": item.get("source"),
                "field_names": (item.get("field_names") or [])[:MAX_FIELDS],
                "method_names": (item.get("method_names") or [])[:MAX_METHODS],
                "evidence": (item.get("evidence") or [])[:MAX_SOURCES],
                "score": int(item.get("score") or 0),
            }
            if item.get("matched_terms"):
                compact["matched_terms"] = item["matched_terms"]
            ranked.append(compact)
        ranked.sort(key=lambda item: (-item["score"], item["name"] or ""))
        return ranked[:limit]

    def _package(self, path: str, source: str) -> dict[str, Any]:
        path = path.strip()
        stats = self.package_stats.setdefault(
            path,
            {
                "sources": set(),
                "function_count": 0,
                "type_names": set(),
            },
        )
        stats["sources"].add(source)
        return stats

    def _functions(self) -> list[dict[str, Any]]:
        functions = getattr(self.analyzer, "user_functions", None)
        if not functions:
            functions = self.goresym.get("UserFunctions")
        if not functions:
            functions = self.goresym.get("Functions")
        return [item for item in _as_list(functions) if isinstance(item, dict)]

    def _build_info(self) -> dict[str, Any]:
        build_info = self.goresym.get("BuildInfo")
        return build_info if isinstance(build_info, dict) else {}

    def _module_path(self) -> str:
        build_info = self._build_info()
        path = _safe_str(build_info.get("Path"))
        if path:
            return path
        main = build_info.get("Main")
        if isinstance(main, dict):
            return _safe_str(main.get("Path"))
        return ""

    def _note(self, text: str) -> None:
        _append_unique(self.notes, text, MAX_NOTES)


def _empty_type_item(source: str) -> dict[str, Any]:
    return {
        "name": "",
        "short_name": "",
        "package": "",
        "kind": "",
        "source": source,
        "field_names": [],
        "method_names": [],
        "evidence": [source],
        "score": 0,
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("Items", "Types", "Interfaces", "Values", "Entries"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
        return [value]
    return []


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _first_str(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _safe_str(record.get(key))
        if value:
            return value
    return ""


def _path_from_build_dep(dep: Any) -> str:
    if isinstance(dep, str):
        return dep
    if isinstance(dep, dict):
        return _safe_str(dep.get("Path") or dep.get("path") or dep.get("ModulePath"))
    return ""


def _package_from_function(name: str) -> str:
    name = _strip_instantiation(name)
    receiver_start = name.find(".(")
    if receiver_start >= 0:
        return name[:receiver_start]
    receiver_match = re.match(r"^(?P<pkg>.+)\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*", name)
    if receiver_match:
        return receiver_match.group("pkg")
    if "." in name:
        return name.rsplit(".", 1)[0]
    return ""


def _receiver_type_from_function(name: str) -> dict[str, str] | None:
    name = _strip_instantiation(name)
    pointer_match = re.match(r"^(?P<pkg>.+)\.\(\*(?P<type>[^)]+)\)\.(?P<method>[^.]+)$", name)
    if pointer_match:
        return {
            "package": pointer_match.group("pkg"),
            "name": _clean_type_name(pointer_match.group("type")),
            "method": pointer_match.group("method"),
        }

    value_match = re.match(
        r"^(?P<pkg>.+)\.(?P<type>[A-Za-z_][A-Za-z0-9_]*)\.(?P<method>[A-Za-z_][A-Za-z0-9_]*)$",
        name,
    )
    if value_match:
        return {
            "package": value_match.group("pkg"),
            "name": value_match.group("type"),
            "method": value_match.group("method"),
        }
    return None


def _method_name_from_function(name: str) -> str:
    if "." not in name:
        return name
    return name.rsplit(".", 1)[-1]


def _package_from_type_name(name: str) -> str:
    name = _strip_instantiation(name)
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[0]


def _short_type_name(name: str) -> str:
    name = _strip_instantiation(_safe_str(name))
    if not name:
        return ""
    if name.startswith("*"):
        name = name[1:]
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    return _clean_type_name(name)


def _clean_type_name(name: str) -> str:
    name = name.strip()
    if name.startswith("*"):
        name = name[1:]
    return name.strip("()")


def _qualified_name(package: str, short_name: str) -> str:
    package = _safe_str(package)
    short_name = _safe_str(short_name)
    if package and short_name and not short_name.startswith(package + "."):
        return f"{package}.{short_name}"
    return short_name


def _strip_instantiation(name: str) -> str:
    return re.sub(r"\[[^\]]+\]", "", _safe_str(name))


def _infer_kind(record: dict[str, Any]) -> str:
    if record.get("Fields") or record.get("StructFields") or record.get("fields"):
        return "struct"
    if record.get("Methods") or record.get("Imethods") or record.get("methods"):
        return "interface_or_named_type"
    if record.get("Elem") is not None:
        return "container_or_pointer"
    return ""


def _names_from_records(value: Any, limit: int) -> list[str]:
    names = []
    for item in _as_list(value):
        name = ""
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = _first_str(item, "Name", "name", "FieldName", "MethodName", "String")
        if name:
            _append_unique(names, name, limit)
    return names


def _matched_terms(text: str) -> list[str]:
    lowered = _safe_str(text).lower()
    if not lowered:
        return []
    return [term for term in INTERESTING_TERMS if term in lowered][:12]


def _package_kind(path: str, module_path: str) -> str:
    path = _safe_str(path)
    module_path = _safe_str(module_path)
    if module_path and path == module_path:
        return "main_module"
    if module_path and path.startswith(module_path + "/"):
        return "main_module"
    if path.startswith(NOISY_PACKAGE_PREFIXES):
        return "standard_or_runtime"
    if "." in path.split("/", 1)[0]:
        return "third_party_or_dependency"
    if path == "main" or path.startswith("main."):
        return "main_package"
    return "unknown"


def _append_unique(values: list[Any], value: Any, limit: int) -> None:
    if value in values or len(values) >= limit:
        return
    values.append(value)


def package_frequency(function_names: list[str]) -> Counter[str]:
    """Small public helper useful for tests and ad hoc inspection."""

    counter: Counter[str] = Counter()
    for name in function_names:
        package = _package_from_function(name)
        if package:
            counter[package] += 1
    return counter


def likely_application_packages(packages: list[dict[str, Any]]) -> list[str]:
    """Return non-runtime-looking package paths from an analyze_go_types result."""

    result = []
    for package in packages:
        path = _safe_str(package.get("path") if isinstance(package, dict) else package)
        if path and not path.startswith(NOISY_PACKAGE_PREFIXES):
            result.append(path)
    return result
