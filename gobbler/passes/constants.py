import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone.x86 import *

from gobbler.arch import canonical_register as canonical_x86_register
from gobbler.arch import memory_target_access
from gobbler.binary import BinarySection

DEFAULT_ARRAY_WINDOW = 0x100
MAX_ARRAY_WINDOW = 0x1000
MIN_ARRAY_SIZE = 16
METADATA_SAMPLE_LIMIT = 0x10000
MAX_LARGE_COPY_ARRAY_BYTES = 0x10000
EXCLUDED_ARRAY_SECTIONS = {
    ".text",
    ".pdata",
    ".xdata",
    ".reloc",
    ".idata",
    ".bss",
    ".noptrbss",
    ".noptrdata",
    ".gopclntab",
}


@dataclass
class ArrayDump:
    array_id: str
    section: str
    va: int
    size: int
    data: bytes
    referenced_by: list[str]
    reasons: list[str]

    def metadata(self) -> dict[str, Any]:
        sample = self.data[: min(len(self.data), METADATA_SAMPLE_LIMIT)]
        return {
            "id": self.array_id,
            "section": self.section,
            "va": hex(self.va),
            "size": hex(self.size),
            "entropy": round(shannon_entropy(sample), 3),
            "entropy_sampled": len(sample) < len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "sha256_prefix": hashlib.sha256(self.data).hexdigest()[:16],
            "printable_ratio": round(printable_ratio(sample), 3),
            "magic_offsets": magic_offsets(self.data[: min(len(self.data), 0x20000)])[:16],
            "referenced_by": self.referenced_by,
            "reasons": self.reasons,
            "hex_preview": self.data[:64].hex(),
            "ascii_preview": ascii_preview(self.data[:96]),
        }


def analyze_constants(analyzer: Any, graph: dict[str, list[Any]]) -> tuple[dict[str, Any], list[ArrayDump]]:
    sections = section_ranges(analyzer)
    refs = collect_data_references(analyzer, graph, sections)
    large_copies = collect_large_copy_arrays(analyzer, graph, sections)
    windows = collect_referenced_array_windows(sections, refs, large_copies)
    arrays = assign_array_ids(large_copies + windows)

    constants = {
        "global_strings": global_strings(analyzer, refs),
        "constant_arrays": [array.metadata() for array in arrays],
        "numeric_constants": collect_numeric_constants(analyzer, graph),
    }
    return constants, arrays


def dump_constant_arrays(arrays: list[ArrayDump], output_dir: Path) -> list[dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    dumped = []
    for array in arrays:
        filename = f"{array.array_id}_{array.section.strip('.')}_{array.va:x}_{array.size:x}.bin"
        path = output_dir / filename
        path.write_bytes(array.data)
        dumped.append({"id": array.array_id, "path": str(path), "size": hex(array.size)})
    return dumped


def section_ranges(analyzer: Any) -> list[BinarySection]:
    return analyzer.binary_view.sections()


def collect_data_references(
    analyzer: Any, graph: dict[str, list[Any]], sections: list[BinarySection]
) -> dict[int, set[str]]:
    refs: dict[int, set[str]] = {}
    for function_name in graph:
        function = function_by_name(analyzer, function_name)
        if function is None:
            continue
        for insn in analyzer.function_content(function):
            for operand in insn.operands:
                target = None
                if operand.type == X86_OP_MEM:
                    resolved = memory_target_access(insn, operand, analyzer.binary_view.arch)
                    if resolved is not None:
                        target, _access = resolved
                elif operand.type == X86_OP_IMM:
                    target = int(operand.imm)
                if target is None:
                    continue
                section = section_for_va(sections, target)
                if section is None or is_excluded_array_section(section.name):
                    continue
                refs.setdefault(target, set()).add(function_name)
    return refs


def collect_large_copy_arrays(
    analyzer: Any, graph: dict[str, list[Any]], sections: list[BinarySection]
) -> list[ArrayDump]:
    arrays = []
    for function_name in graph:
        function = function_by_name(analyzer, function_name)
        if function is None:
            continue
        register_ints: dict[str, int] = {}
        recent_source: int | None = None
        for insn in analyzer.function_content(function):
            mnemonic = insn.mnemonic.lower()
            if mnemonic in {"mov", "movabs"} and len(insn.operands) >= 2:
                dest = canonical_register(insn.operands[0].reg) if insn.operands[0].type == X86_OP_REG else None
                src = insn.operands[1]
                if dest and src.type == X86_OP_IMM:
                    register_ints[dest] = int(src.imm)
                    if section_for_va(sections, int(src.imm)) is not None:
                        recent_source = int(src.imm)
                elif dest:
                    register_ints.pop(dest, None)
            if mnemonic == "lea" and len(insn.operands) >= 2 and insn.operands[1].type == X86_OP_MEM:
                target = memory_target_access(insn, insn.operands[1], analyzer.binary_view.arch)
                if target is not None:
                    recent_source = target[0]
            if "movs" not in mnemonic:
                continue
            size = copy_size_from_instruction(mnemonic, register_ints)
            if size is None or recent_source is None or size < MIN_ARRAY_SIZE:
                continue
            section = section_for_va(sections, recent_source)
            if section is None or is_excluded_array_section(section.name):
                continue
            data = read_section_bytes(section, recent_source, min(size, MAX_LARGE_COPY_ARRAY_BYTES))
            if len(data) < MIN_ARRAY_SIZE:
                continue
            arrays.append(
                ArrayDump(
                    array_id="",
                    section=section.name,
                    va=recent_source,
                    size=size,
                    data=data,
                    referenced_by=[function_name],
                    reasons=["large_copy_source"],
                )
            )
    return arrays


def collect_referenced_array_windows(
    sections: list[BinarySection],
    refs: dict[int, set[str]],
    large_copies: list[ArrayDump],
) -> list[ArrayDump]:
    arrays = []
    large_ranges = [(array.va, array.va + array.size) for array in large_copies]
    for va, functions in refs.items():
        if any(start <= va < end for start, end in large_ranges):
            continue
        section = section_for_va(sections, va)
        if section is None or is_excluded_array_section(section.name):
            continue
        if looks_like_go_string_address(va, functions):
            continue
        start = max(section.va, align_down(va, 16))
        data = read_section_bytes(section, start, DEFAULT_ARRAY_WINDOW)
        if len(data) < MIN_ARRAY_SIZE:
            continue
        if is_mostly_zero(data):
            continue
        arrays.append(
            ArrayDump(
                array_id="",
                section=section.name,
                va=start,
                size=len(data),
                data=data,
                referenced_by=sorted(functions),
                reasons=["referenced_global_data"],
            )
        )
    return merge_array_windows(arrays)


def assign_array_ids(arrays: list[ArrayDump]) -> list[ArrayDump]:
    arrays = sorted(arrays, key=lambda item: (item.section, item.va, item.size))
    result = []
    seen = set()
    for array in arrays:
        key = (array.section, array.va, array.size, hashlib.sha256(array.data).hexdigest())
        if key in seen:
            continue
        seen.add(key)
        array.array_id = f"array_{len(result)}"
        result.append(array)
    return result


def merge_array_windows(arrays: list[ArrayDump]) -> list[ArrayDump]:
    if not arrays:
        return []
    arrays = sorted(arrays, key=lambda item: (item.section, item.va))
    merged = [arrays[0]]
    for array in arrays[1:]:
        prev = merged[-1]
        prev_end = prev.va + prev.size
        if array.section == prev.section and array.va <= prev_end:
            new_end = min(max(prev_end, array.va + array.size), prev.va + MAX_ARRAY_WINDOW)
            prev.data = prev.data[: new_end - prev.va]
            prev.size = len(prev.data)
            prev.referenced_by = sorted(set(prev.referenced_by) | set(array.referenced_by))
            prev.reasons = sorted(set(prev.reasons) | set(array.reasons))
            continue
        merged.append(array)
    return merged


def global_strings(analyzer: Any, refs: dict[int, set[str]]) -> list[dict[str, Any]]:
    strings = []
    for address, value in sorted(analyzer.string_data.items()):
        strings.append(
            {
                "address": hex(address),
                "length": len(value.encode("utf-8", errors="replace")),
                "value": value,
                "classification": classify_string(value),
                "referenced_by": sorted(refs.get(address, set())),
            }
        )
    return strings


def collect_numeric_constants(analyzer: Any, graph: dict[str, list[Any]]) -> list[dict[str, Any]]:
    constants: dict[int, set[str]] = {}
    for function_name in graph:
        function = function_by_name(analyzer, function_name)
        if function is None:
            continue
        for insn in analyzer.function_content(function):
            for operand in insn.operands:
                if operand.type != X86_OP_IMM:
                    continue
                value = int(operand.imm)
                if value < 0x100:
                    continue
                constants.setdefault(value, set()).add(function_name)
    result = []
    for value, functions in sorted(constants.items(), key=lambda item: item[0]):
        result.append(
            {
                "value": hex(value),
                "decimal": value,
                "classification": classify_numeric_constant(value),
                "referenced_by": sorted(functions),
            }
        )
    return result[:500]


def function_by_name(analyzer: Any, name: str) -> dict[str, Any] | None:
    if name in analyzer.user_by_name:
        return analyzer.user_by_name[name]
    for function in analyzer.user_functions:
        if function.get("FullName") == name:
            return function
    return None


def section_for_va(sections: list[BinarySection], va: int) -> BinarySection | None:
    for section in sections:
        if section.va <= va < section.end:
            return section
    return None


def is_excluded_array_section(name: str) -> bool:
    lowered = name.lower()
    return lowered in EXCLUDED_ARRAY_SECTIONS or lowered.startswith(".debug")


def read_section_bytes(section: BinarySection, va: int, size: int) -> bytes:
    offset = va - section.va
    if offset < 0:
        return b""
    return section.data[offset : offset + min(size, section.end - va)]


def canonical_register(reg_id: int) -> str | None:
    return canonical_x86_register(reg_id)


def copy_size_from_instruction(mnemonic: str, register_ints: dict[str, int]) -> int | None:
    count = register_ints.get("RCX")
    if count is None:
        return None
    width = 1
    if "movsq" in mnemonic:
        width = 8
    elif "movsd" in mnemonic:
        width = 4
    elif "movsw" in mnemonic:
        width = 2
    return count * width


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)
    return printable / len(data)


def ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def magic_offsets(data: bytes) -> list[dict[str, Any]]:
    hits = []
    needles = {
        b"MZ": "MZ",
        b"PE\x00\x00": "PE",
        b"\x7fELF": "ELF",
        b"PK\x03\x04": "PK",
        b"\x1f\x8b": "gzip",
        b"\x78\x9c": "zlib",
        b"\x78\xda": "zlib",
    }
    for needle, label in needles.items():
        start = 0
        while True:
            offset = data.find(needle, start)
            if offset == -1:
                break
            hits.append({"offset": hex(offset), "magic": label})
            start = offset + 1
            if len(hits) >= 16:
                return hits
    return hits


def align_down(value: int, alignment: int) -> int:
    return value - (value % alignment)


def is_mostly_zero(data: bytes) -> bool:
    return data.count(0) / len(data) > 0.9


def looks_like_go_string_address(va: int, functions: set[str]) -> bool:
    return False


def classify_string(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "\\" in value or "/" in value:
        return "path_or_url_fragment"
    if lowered.endswith(".dll"):
        return "dll_name"
    if lowered in {"temp", "tmp", "path", "home", "userprofile", "appdata"}:
        return "environment_variable"
    if len(value) > 120:
        return "long_text"
    return "string"


def classify_numeric_constant(value: int) -> str:
    if value == 0x5A4D:
        return "MZ_magic"
    if value == 0x4550:
        return "PE_magic"
    if value == 0x464C457F:
        return "ELF_magic"
    if value == 0x3000:
        return "MEM_COMMIT_OR_RESERVE"
    if value in {0x10, 0x20, 0x40, 0x80}:
        return "memory_protection_flag"
    if 1 <= value <= 65535:
        return "small_constant_or_port"
    return "numeric_constant"
