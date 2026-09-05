"""Module-aware provenance, never a trust or maliciousness determination.

GoReSym's UserFunctions includes dependencies; it does not establish application
ownership. Missing metadata therefore produces unknown ownership, not an implicit
application or trusted-library label.
"""
from __future__ import annotations

import re
from typing import Any, Iterable


def _records(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _path(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _within(package: str, module: str) -> bool:
    return bool(module) and (package == module or package.startswith(module + "/"))


def package_from_function(function: str, module_paths: Iterable[str] = ()) -> str:
    """Recover a package without confusing domain dots or method receivers.

    Known module roots disambiguate dots in module names (e.g. yaml.v3).
    Compiler-generated symbols without ordinary package syntax remain unknown.
    """
    name = re.sub(r"\[[^\]]*\]", "", _path(function))
    if not name or name.startswith(("type:", "go:")):
        return ""
    for module in sorted(module_paths, key=len, reverse=True):
        if name.startswith(module + ".") and "/" not in name[len(module) + 1:]:
            return module
    last_slash = name.rfind("/")
    separator = name.find(".", last_slash + 1)
    return name[:separator] if separator >= 0 else ""


class OwnershipClassifier:
    def __init__(self, goresym: dict[str, Any] | None = None):
        goresym = goresym if isinstance(goresym, dict) else {}
        build = goresym.get("BuildInfo")
        build = build if isinstance(build, dict) else {}
        main = build.get("Main")
        self.main_module = _path(main.get("Path")) if isinstance(main, dict) else ""
        # BuildInfo.Path is the command's import path, not the module root.
        self.command_path = _path(build.get("Path"))
        if self.main_module == "command-line-arguments":
            self.main_module = ""
        self.dependencies = sorted({
            path for dep in build.get("Deps") or []
            if (path := _path(dep.get("Path")) if isinstance(dep, dict) else _path(dep))
        })
        self.modules = [self.main_module, *self.dependencies]
        self.standard = {
            _path(record.get("FullName") or record.get("Name"))
            for record in _records(goresym.get("StdFunctions"))
        } - {""}
        self.user = {
            _path(record.get("FullName") or record.get("Name"))
            for record in _records(goresym.get("UserFunctions"))
        } - {""}
        self.standard_packages = {package_from_function(name) for name in self.standard} - {""}

    def classify_package(self, package: str) -> dict[str, Any]:
        result: dict[str, Any] = {"classification": "unknown", "package": package, "provenance": []}
        candidates = [(self.main_module, "application", "goresym.BuildInfo.Main.Path")]
        candidates.extend((module, "dependency", "goresym.BuildInfo.Deps.Path") for module in self.dependencies)
        matches = [candidate for candidate in candidates if _within(package, candidate[0])]
        if matches:
            module, kind, source = max(matches, key=lambda item: len(item[0]))
            result.update(classification=kind, module=module, provenance=[source])
        elif package == "main":
            result.update(classification="application", provenance=["go_main_package_symbol"])
        elif self.command_path != "command-line-arguments" and package == self.command_path and package:
            result.update(classification="application", provenance=["goresym.BuildInfo.Path (exact command package only)"])
        elif package in self.standard_packages:
            result.update(classification="standard_library", provenance=["goresym.StdFunctions package membership"])
        else:
            result["provenance"] = ["ownership_metadata_unavailable_or_unmatched"]
        return result

    def classify(self, function: str) -> dict[str, Any]:
        package = package_from_function(function, self.modules)
        result = self.classify_package(package)
        if function in self.standard and function in self.user:
            return {"classification": "unknown", "package": package, "provenance": ["conflicting_goresym_function_membership"]}
        if function in self.standard:
            return {"classification": "standard_library", "package": package, "provenance": ["goresym.StdFunctions exact symbol"]}
        # A package name resembling a standard package is insufficient when
        # GoReSym explicitly lists this particular symbol outside StdFunctions.
        if function in self.user and result["classification"] == "standard_library":
            result.update(classification="unknown", provenance=["goresym.UserFunctions; standard package name collision"])
        if function in self.user:
            result["provenance"].append("goresym.UserFunctions (includes dependencies)")
        return result


def build_ownership(goresym: dict[str, Any] | None, functions: Iterable[str] | None = None) -> dict[str, Any]:
    classifier = OwnershipClassifier(goresym)
    names = set(functions) if functions is not None else classifier.user | classifier.standard
    return {
        "main_module": classifier.main_module,
        "command_path": classifier.command_path,
        "dependency_modules": classifier.dependencies,
        "functions": {name: classifier.classify(name) for name in sorted(names) if name},
        "notes": ["Ownership describes provenance, not trust; dependency behavior remains relevant.",
                  "Unmatched symbols remain unknown; UserFunctions alone does not establish application ownership."],
    }


def lookup_function_ownership(function: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context if isinstance(context, dict) else {}
    ownership = context.get("ownership", context)
    if not isinstance(ownership, dict):
        ownership = {}
    record = (ownership.get("functions") or {}).get(function)
    if isinstance(record, dict) and record.get("classification"):
        return record
    classifier = OwnershipClassifier({"BuildInfo": {
        "Main": {"Path": ownership.get("main_module")},
        "Path": ownership.get("command_path"),
        "Deps": [{"Path": path} for path in ownership.get("dependency_modules") or []],
    }})
    return classifier.classify(function)


def is_library_function(function: str, context: dict[str, Any] | None = None) -> bool:
    return lookup_function_ownership(function, context)["classification"] in {"dependency", "standard_library"}


def is_app_function(function: str, context: dict[str, Any] | None = None) -> bool:
    return lookup_function_ownership(function, context)["classification"] == "application"


def should_analyze_function(function: str, context: dict[str, Any] | None = None) -> bool:
    """Keep dependency and unknown behavior visible alongside application code."""
    return bool(function) and lookup_function_ownership(function, context)["classification"] != "standard_library"
