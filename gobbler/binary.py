from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gobbler.arch import SUPPORTED_ARCHES, word_size


@dataclass(frozen=True)
class BinarySection:
    name: str
    va: int
    end: int
    data: bytes


class BinaryView:
    def __init__(self, binary: Any):
        self.binary = binary
        self.format = detect_format(binary)
        self.arch = detect_arch(binary)
        self.imagebase = int(getattr(binary, "imagebase", 0) or 0)

    def ensure_supported(self) -> None:
        if self.format not in {"pe", "elf"}:
            raise RuntimeError(f"Unsupported binary format: {self.format}")
        if self.arch not in SUPPORTED_ARCHES:
            raise RuntimeError(f"Unsupported architecture for {self.format}: {self.arch}")

    @property
    def pointer_size(self) -> int:
        return word_size(self.arch)

    def section_va(self, section: Any) -> int:
        virtual_address = int(getattr(section, "virtual_address", 0) or 0)
        if self.format == "pe":
            return self.imagebase + virtual_address
        return virtual_address

    def sections(self) -> list[BinarySection]:
        ranges = []
        for section in getattr(self.binary, "sections", []) or []:
            data = bytes(getattr(section, "content", b"") or b"")
            if not data:
                continue
            start = self.section_va(section)
            ranges.append(BinarySection(str(getattr(section, "name", "")), start, start + len(data), data))
        return ranges

    def info(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "arch": self.arch,
            "imagebase": hex(self.imagebase),
            "entrypoint": hex(int(getattr(self.binary, "entrypoint", 0) or 0)),
        }

    def imports(self) -> dict[str, Any]:
        if self.format == "pe":
            return pe_imports(self.binary)
        if self.format == "elf":
            return elf_imports(self.binary)
        return {"format": self.format, "libraries": [], "functions": []}


def detect_format(binary: Any) -> str:
    value = str(getattr(binary, "format", "")).lower()
    type_name = type(binary).__name__.lower()
    if "pe" in value or "pe" in type_name:
        return "pe"
    if "elf" in value or "elf" in type_name:
        return "elf"
    if "macho" in value or "mach" in type_name:
        return "macho"
    return value or type_name or "unknown"


def detect_arch(binary: Any) -> str:
    header = getattr(binary, "header", None)
    candidates = [
        getattr(header, "machine", None),
        getattr(header, "machine_type", None),
        getattr(header, "cpu_type", None),
    ]
    text = " ".join(str(candidate).lower() for candidate in candidates if candidate is not None)
    if any(token in text for token in ("amd64", "x86_64", "x86-64")):
        return "x86_64"
    if any(token in text for token in ("i386", "x86")):
        return "x86"
    if "aarch64" in text or "arm64" in text:
        return "arm64"
    if "loongarch" in text:
        return "loongarch"
    return text or "unknown"


def pe_imports(binary: Any) -> dict[str, Any]:
    libraries: dict[str, list[str]] = {}
    if hasattr(binary, "imports"):
        for imported_library in binary.imports:
            entries = []
            for entry in imported_library.entries:
                if entry.name:
                    entries.append(entry.name)
                elif entry.is_ordinal:
                    entries.append(f"ordinal_{entry.ordinal}")
            libraries[imported_library.name] = sorted(entries)
    return {"format": "pe", "libraries": libraries, "functions": sorted({name for names in libraries.values() for name in names})}


def elf_imports(binary: Any) -> dict[str, Any]:
    libraries = sorted(str(item) for item in (getattr(binary, "libraries", []) or []))
    functions = []
    for function in getattr(binary, "imported_functions", []) or []:
        name = getattr(function, "name", None)
        if name:
            functions.append(str(name))
    return {"format": "elf", "libraries": libraries, "functions": sorted(set(functions))}
