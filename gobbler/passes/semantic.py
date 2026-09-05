import hashlib
import math
import re
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

import lief
from capstone.x86 import *

from gobbler.arch import canonical_register as canonical_x86_register
from gobbler.arch import memory_target, memory_target_access, rip_target as x86_rip_target
from gobbler.binary import BinarySection
from gobbler.utils.ownership import build_ownership, should_analyze_function


HIGH_ENTROPY_THRESHOLD = 7.2
CHUNK_SIZE = 0x1000
MIN_BLOB_SIZE = 0x800
LARGE_COPY_THRESHOLD = 0x4000
ENTROPY_SAMPLE_LIMIT = 0x10000

EXECUTE_PROTECTIONS = {
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

ALLOCATION_TYPES = {
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
}

MAGIC_VALUES = {
    0x5A4D: "MZ",
    0x4550: "PE",
    0x464C457F: "ELF",
    0x04034B50: "PK",
    0x8B1F: "gzip",
    0x9C78: "zlib",
    0xDA78: "zlib",
}

TRANSFORM_MNEMONICS = {
    "xor": "xor",
    "add": "add",
    "sub": "sub",
    "rol": "rotate",
    "ror": "rotate",
    "not": "not",
    "bswap": "byte_swap",
    "shl": "shift",
    "shr": "shift",
    "sar": "shift",
}

TRANSFORM_CALL_HINTS = {
    "encoding/base64": "base64",
    "encoding/hex": "hex",
    "compress/gzip": "gzip",
    "compress/zlib": "zlib",
    "crypto/aes": "aes",
    "crypto/rc4": "rc4",
    "chacha20": "chacha20",
    "runtime.slicebytetostring": "bytes_to_string",
    "bytes.(*Buffer).String": "bytes_to_string",
}

LOADER_CALL_HINTS = {
    "syscall.LoadLibrary": "dynamic_library_load",
    "syscall.NewLazyDLL": "dynamic_library_load",
    "syscall.NewLazySystemDLL": "dynamic_library_load",
    "syscall.(*LazyDLL).Load": "dynamic_library_load",
    "syscall.(*DLL).FindProc": "dynamic_import_resolution",
    "syscall.(*LazyDLL).NewProc": "dynamic_import_resolution",
    "syscall.GetProcAddress": "dynamic_import_resolution",
    "syscall.(*LazyProc).Find": "dynamic_import_resolution",
    "syscall.(*LazyProc).Call": "dynamic_syscall_call",
    "syscall.Syscall": "raw_syscall",
    "syscall.SyscallN": "raw_syscall",
    "syscall.Mmap": "memory_allocation",
    "syscall.Mprotect": "memory_protection_change",
    "golang.org/x/sys/unix.Mmap": "memory_allocation",
    "golang.org/x/sys/unix.Mprotect": "memory_protection_change",
    "unix.Mmap": "memory_allocation",
    "unix.Mprotect": "memory_protection_change",
    "syscall.Exec": "process_execution",
    "syscall.ForkExec": "process_execution",
    "os/exec.(*Cmd).Start": "process_execution",
    "os/exec.(*Cmd).Run": "process_execution",
    "os/exec.(*Cmd).Output": "process_execution",
    "os/exec.(*Cmd).CombinedOutput": "process_execution",
    "dlopen": "dynamic_library_load",
    "dlsym": "dynamic_import_resolution",
    "golang.org/x/sys/windows.LoadDLL": "dynamic_library_load",
    "golang.org/x/sys/windows.NewLazyDLL": "dynamic_library_load",
    "golang.org/x/sys/windows.NewLazySystemDLL": "dynamic_library_load",
    "golang.org/x/sys/windows.(*LazyDLL).Load": "dynamic_library_load",
    "golang.org/x/sys/windows.(*DLL).FindProc": "dynamic_import_resolution",
    "golang.org/x/sys/windows.(*LazyDLL).NewProc": "dynamic_import_resolution",
    "golang.org/x/sys/windows.(*LazyProc).Find": "dynamic_import_resolution",
    "golang.org/x/sys/windows.(*LazyProc).Call": "dynamic_syscall_call",
    "windows.LoadDLL": "dynamic_library_load",
    "windows.NewLazyDLL": "dynamic_library_load",
    "windows.NewLazySystemDLL": "dynamic_library_load",
    "windows.(*LazyDLL).Load": "dynamic_library_load",
    "windows.(*DLL).FindProc": "dynamic_import_resolution",
    "windows.(*LazyDLL).NewProc": "dynamic_import_resolution",
    "windows.(*LazyProc).Find": "dynamic_import_resolution",
    "windows.(*LazyProc).Call": "dynamic_syscall_call",
    "VirtualAlloc": "memory_allocation",
    "VirtualProtect": "memory_protection_change",
    "LoadLibrary": "dynamic_library_load",
    "GetProcAddress": "dynamic_import_resolution",
    "CreateThread": "thread_creation",
}


@dataclass
class DataReference:
    function: str
    instruction: int
    target: int
    access: str


@dataclass
class LargeCopy:
    function: str
    instruction: int
    source: int | None
    size: int | None
    mnemonic: str


@dataclass
class MidFunctionTransfer:
    source_function: str
    instruction: int
    mnemonic: str
    transfer_type: str
    target: int
    target_function: str
    target_kind: str
    target_offset: int
    is_internal_branch: bool


@dataclass
class IndirectCall:
    function: str
    instruction: int
    operand: str
    call_kind: str
    classification: str
    evidence: list[str]
    provenance: dict[str, Any] | None = None


@dataclass
class SemanticScanner:
    analyzer: Any
    graph: dict[str, list[Any]]
    sections: list[BinarySection] = field(init=False)
    ownership: dict[str, Any] = field(init=False)
    data_references: list[DataReference] = field(default_factory=list)
    large_copies: list[LargeCopy] = field(default_factory=list)
    mid_function_transfers: list[MidFunctionTransfer] = field(default_factory=list)
    indirect_calls: list[IndirectCall] = field(default_factory=list)
    function_features: dict[str, dict[str, Any]] = field(default_factory=dict)
    sub_timings: list[dict[str, Any]] = field(default_factory=list)
    user_range_starts: list[int] = field(init=False)
    std_range_starts: list[int] = field(init=False)

    def __post_init__(self) -> None:
        self.ownership = build_ownership(getattr(self.analyzer, "goresym", {}), self.graph)
        self.sections = self._section_ranges()
        self.user_range_starts = [function["Start"] for function in self.analyzer.user_ranges]
        self.std_range_starts = [function["Start"] for function in self.analyzer.std_ranges]

    def analyze(self) -> dict[str, Any]:
        self._timed("scan_reachable_functions", self._scan_reachable_functions)
        mid_function_transfers = self._timed("mid_function_control_transfers", self._mid_function_control_transfers)
        indirect_calls = self._timed("indirect_calls", self._indirect_calls)
        blobs = self._timed("notable_data_blobs", self._notable_data_blobs)
        transformers = self._timed("data_transformers", lambda: self._data_transformers(blobs))
        loaders = self._timed("loader_behaviors", lambda: self._loader_behaviors(transformers))
        embedded_artifacts = self._timed(
            "embedded_artifacts", lambda: self._embedded_artifacts(blobs, transformers, loaders)
        )

        return {
            "binary_info": self.analyzer.binary_view.info(),
            "ownership": self.ownership,
            "imports": self.analyzer.binary_view.imports(),
            "pe_imports": pe_imports(self.analyzer.binary),
            "mid_function_control_transfers": mid_function_transfers,
            "indirect_calls": indirect_calls,
            "notable_data_blobs": blobs,
            "data_transformers": transformers,
            "loader_behaviors": loaders,
            "memory_operations": [
                operation
                for features in self.function_features.values()
                for operation in features.get("memory_operations", [])
            ],
            "embedded_artifacts": embedded_artifacts,
            "assessment_hints": assessment_hints(
                blobs,
                transformers,
                loaders,
                embedded_artifacts,
                mid_function_transfers,
                indirect_calls,
            ),
            "scanner_timing": self.sub_timings,
        }

    def _timed(self, name: str, callback):
        started = time.monotonic()
        value = callback()
        self.sub_timings.append({"name": name, "duration_seconds": round(time.monotonic() - started, 3)})
        return value

    def _section_ranges(self) -> list[BinarySection]:
        return self.analyzer.binary_view.sections()

    def _scan_reachable_functions(self) -> None:
        for name in self.graph:
            try:
                function = self.analyzer.function_by_entry_name(name)
            except KeyError:
                function = self._function_by_full_name(name)
            if function is None:
                continue
            self.function_features[name] = self._scan_function(name, function)

    def _function_by_full_name(self, name: str) -> dict[str, Any] | None:
        for function in self.analyzer.user_functions:
            if function.get("FullName") == name:
                return function
        return None

    def _scan_function(self, name: str, function: dict[str, Any]) -> dict[str, Any]:
        features: dict[str, Any] = {
            "transform_ops": set(),
            "magic_checks": set(),
            "backward_jumps": 0,
            "byte_memory_ops": 0,
            "large_copies": [],
            "referenced_sections": set(),
            "loader_hints": set(),
            "allocation_constants": set(),
            "protection_constants": set(),
            "internal_mid_function_jumps": 0,
        }
        register_ints: dict[str, int] = {}
        register_provenance: dict[str, dict[str, Any]] = {}
        recent_source: int | None = None

        for insn in self.analyzer.function_content(function):
            mnemonic = insn.mnemonic.lower()
            self._record_operand_references(name, insn, features)
            self._record_immediate_features(insn, features)
            self._record_instruction_features(insn, features)
            self._record_mid_function_transfer(name, function, insn, features)
            self._record_indirect_call(name, insn, register_provenance)

            if mnemonic in {"mov", "movabs"} and len(insn.operands) >= 2:
                dest = canonical_register(insn.operands[0].reg) if insn.operands[0].type == X86_OP_REG else None
                src = insn.operands[1]
                if dest and src.type == X86_OP_IMM:
                    register_ints[dest] = int(src.imm)
                elif dest:
                    register_ints.pop(dest, None)
                update_register_provenance(insn, register_provenance, self.analyzer.binary_view.arch)

            if mnemonic == "lea" and len(insn.operands) >= 2 and insn.operands[1].type == X86_OP_MEM:
                target = memory_target(insn, insn.operands[1], self.analyzer.binary_view.arch)
                if target is not None:
                    recent_source = target
                update_register_provenance(insn, register_provenance, self.analyzer.binary_view.arch)

            if "movs" in mnemonic:
                copy_size = copy_size_from_instruction(mnemonic, register_ints)
                if copy_size is not None and copy_size >= LARGE_COPY_THRESHOLD:
                    large_copy = LargeCopy(name, insn.address, recent_source, copy_size, mnemonic)
                    self.large_copies.append(large_copy)
                    features["large_copies"].append(large_copy)

            if mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM:
                target_name, _ = self.analyzer.resolve_direct_call(int(insn.operands[0].imm))
                register_provenance["RAX"] = {
                    "kind": "call_return",
                    "call": target_name,
                    "instruction": hex(insn.address),
                }

        features["calls"] = [call.target for call in self.graph.get(name, [])]
        for call in self.graph.get(name, []):
            for hint, label in LOADER_CALL_HINTS.items():
                if hint in call.target:
                    features["loader_hints"].add(label)
            for hint, label in TRANSFORM_CALL_HINTS.items():
                if hint in call.target:
                    features["transform_ops"].add(label)

        features["memory_operations"] = recover_memory_operations(
            self.analyzer, name, function, self.graph.get(name, [])
        )
        return features

    def _record_mid_function_transfer(
        self, source_function: str, function: dict[str, Any], insn, features: dict[str, Any]
    ) -> None:
        if not is_control_transfer(insn):
            return
        if not insn.operands or insn.operands[0].type != X86_OP_IMM:
            return

        target = int(insn.operands[0].imm)
        target_function, target_kind = self._function_containing_va(target)
        if target_function is None:
            return
        target_offset = target - target_function["Start"]
        if target_offset <= 0:
            return

        is_internal = function["Start"] <= target < function["End"]
        if is_internal and insn.mnemonic != "call":
            features["internal_mid_function_jumps"] += 1
            return

        self.mid_function_transfers.append(
            MidFunctionTransfer(
                source_function=source_function,
                instruction=insn.address,
                mnemonic=insn.mnemonic,
                transfer_type=transfer_type(insn),
                target=target,
                target_function=target_function["FullName"],
                target_kind=target_kind,
                target_offset=target_offset,
                is_internal_branch=is_internal,
            )
        )

    def _record_indirect_call(
        self, function: str, insn, register_provenance: dict[str, dict[str, Any]]
    ) -> None:
        if insn.mnemonic.lower() != "call" or not insn.operands:
            return
        operand = insn.operands[0]
        if operand.type == X86_OP_IMM:
            return

        call_kind = indirect_call_kind(operand)
        provenance = indirect_call_provenance(
            operand, register_provenance, self.analyzer.binary_view.arch
        )
        classification, evidence = classify_indirect_call(operand, provenance)
        self.indirect_calls.append(
            IndirectCall(
                function=function,
                instruction=insn.address,
                operand=operand_text(insn),
                call_kind=call_kind,
                classification=classification,
                evidence=evidence,
                provenance=provenance,
            )
        )

    def _record_operand_references(self, function: str, insn, features: dict[str, Any]) -> None:
        for operand in insn.operands:
            target = None
            access = "memory"
            if operand.type == X86_OP_MEM:
                resolved = memory_target_access(insn, operand, self.analyzer.binary_view.arch)
                if resolved is not None:
                    target, access = resolved
            elif operand.type == X86_OP_IMM:
                target = int(operand.imm)
                access = "immediate"

            if target is None:
                continue
            section = self._section_for_va(target)
            if section is None:
                continue
            features["referenced_sections"].add(section.name)
            self.data_references.append(DataReference(function, insn.address, target, access))

    def _record_immediate_features(self, insn, features: dict[str, Any]) -> None:
        for operand in insn.operands:
            if operand.type != X86_OP_IMM:
                continue
            value = int(operand.imm)
            if value in MAGIC_VALUES:
                features["magic_checks"].add(MAGIC_VALUES[value])
            if value & 0x3000 == 0x3000:
                features["allocation_constants"].add(describe_allocation_type(value & 0x3000))
            if value in EXECUTE_PROTECTIONS:
                features["protection_constants"].add(EXECUTE_PROTECTIONS[value])

    def _record_instruction_features(self, insn, features: dict[str, Any]) -> None:
        mnemonic = insn.mnemonic.lower()
        if mnemonic in TRANSFORM_MNEMONICS:
            features["transform_ops"].add(TRANSFORM_MNEMONICS[mnemonic])
        if any(operand.type == X86_OP_MEM and getattr(operand, "size", 0) == 1 for operand in insn.operands):
            features["byte_memory_ops"] += 1
        if is_backward_jump(insn):
            features["backward_jumps"] += 1

    def _section_for_va(self, va: int) -> BinarySection | None:
        for section in self.sections:
            if section.va <= va < section.end:
                return section
        return None

    def _function_containing_va(self, va: int) -> tuple[dict[str, Any] | None, str]:
        user = range_containing_va(self.analyzer.user_ranges, self.user_range_starts, va)
        if user is not None:
            return user, "user"
        std = range_containing_va(self.analyzer.std_ranges, self.std_range_starts, va)
        if std is not None:
            return std, "std"
        return None, "unknown"

    def _mid_function_control_transfers(self) -> list[dict[str, Any]]:
        transfers = []
        seen = set()
        for transfer in self.mid_function_transfers:
            key = (
                transfer.source_function,
                transfer.instruction,
                transfer.target,
                transfer.mnemonic,
            )
            if key in seen:
                continue
            seen.add(key)
            transfers.append(mid_function_transfer_to_dict(transfer))
        return sorted(
            transfers,
            key=lambda item: (
                item["source_function"],
                int(item["instruction"], 16),
                item["transfer_type"],
            ),
        )

    def _indirect_calls(self) -> list[dict[str, Any]]:
        calls = []
        seen = set()
        for call in self.indirect_calls:
            key = (call.function, call.instruction, call.operand)
            if key in seen:
                continue
            seen.add(key)
            calls.append(indirect_call_to_dict(call))
        return sorted(calls, key=lambda item: (item["function"], int(item["address"], 16)))

    def _notable_data_blobs(self) -> list[dict[str, Any]]:
        blobs: list[dict[str, Any]] = []
        referenced_chunks = self._referenced_chunks()
        large_copy_sources = {copy.source for copy in self.large_copies if copy.source is not None}

        large_copy_spans = self._large_copy_blob_spans()
        blobs.extend(large_copy_spans)

        for section in self.sections:
            if is_excluded_data_section(section.name):
                continue
            for offset in range(0, len(section.data), CHUNK_SIZE):
                chunk = section.data[offset : offset + CHUNK_SIZE]
                if len(chunk) < MIN_BLOB_SIZE:
                    continue
                va = section.va + offset
                if any(
                    blob["section"] == section.name
                    and ranges_overlap(
                        va,
                        va + len(chunk),
                        int(blob["va"], 16),
                        int(blob["va"], 16) + int(blob["size"], 16),
                    )
                    for blob in large_copy_spans
                ):
                    continue
                magic = magic_offsets(chunk)
                refs = referenced_chunks.get((section.name, offset // CHUNK_SIZE), [])
                copied = any(va <= source < va + len(chunk) for source in large_copy_sources)
                if not refs and not copied and not magic:
                    continue
                entropy = shannon_entropy(chunk)
                reasons = []
                if entropy >= HIGH_ENTROPY_THRESHOLD:
                    reasons.append("high_entropy")
                if refs:
                    reasons.append("referenced_by_reachable_code")
                if copied:
                    reasons.append("large_copy_source")
                if magic:
                    reasons.append("contains_magic_bytes")
                if not reasons or ("high_entropy" not in reasons and not copied and not magic):
                    continue
                blobs.append(
                    {
                        "id": f"blob_{len(blobs)}",
                        "section": section.name,
                        "va": hex(va),
                        "size": hex(len(chunk)),
                        "entropy": round(entropy, 3),
                        "sha256_prefix": hashlib.sha256(chunk).hexdigest()[:16],
                        "referenced_by": sorted({ref.function for ref in refs}),
                        "reference_count": len(refs),
                        "magic_offsets": magic[:8],
                        "reasons": reasons,
                    }
                )

        return coalesce_blob_runs(blobs)

    def _large_copy_blob_spans(self) -> list[dict[str, Any]]:
        blobs = []
        for span in self._merged_large_copy_spans():
            section = span["section"]
            source = span["start"]
            size = span["end"] - source
            offset = source - section.va
            data = section.data[offset : offset + min(size, ENTROPY_SAMPLE_LIMIT)]
            entropy_sample = data[: min(len(data), ENTROPY_SAMPLE_LIMIT)]
            blobs.append(
                {
                    "id": f"blob_{len(blobs)}",
                    "section": section.name,
                    "va": hex(source),
                    "size": hex(size),
                    "entropy": round(shannon_entropy(entropy_sample), 3),
                    "entropy_sampled": size > len(entropy_sample),
                    "sha256_prefix": hashlib.sha256(data).hexdigest()[:16],
                    "referenced_by": sorted(span["functions"]),
                    "reference_count": span["reference_count"],
                    "magic_offsets": magic_offsets(data[: min(len(data), 0x20000)])[:8],
                    "reasons": ["large_copy_source"],
                }
            )
        return blobs

    def _merged_large_copy_spans(self) -> list[dict[str, Any]]:
        spans = []
        for copy in self.large_copies:
            if copy.source is None or copy.size is None:
                continue
            section = self._section_for_va(copy.source)
            if section is None or is_excluded_data_section(section.name):
                continue
            size = min(copy.size, section.end - copy.source)
            if size < MIN_BLOB_SIZE:
                continue
            spans.append(
                {
                    "section": section,
                    "start": copy.source,
                    "end": copy.source + size,
                    "functions": {copy.function},
                    "reference_count": 1,
                }
            )
        spans.sort(key=lambda item: (item["section"].name, item["start"], item["end"]))
        merged = []
        for span in spans:
            if not merged:
                merged.append(span)
                continue
            previous = merged[-1]
            if span["section"] is previous["section"] and span["start"] <= previous["end"]:
                previous["end"] = max(previous["end"], span["end"])
                previous["functions"].update(span["functions"])
                previous["reference_count"] += span["reference_count"]
                continue
            merged.append(span)
        return merged

    def _referenced_chunks(self) -> dict[tuple[str, int], list[DataReference]]:
        chunks: dict[tuple[str, int], list[DataReference]] = {}
        for ref in self.data_references:
            section = self._section_for_va(ref.target)
            if section is None:
                continue
            chunk_index = (ref.target - section.va) // CHUNK_SIZE
            chunks.setdefault((section.name, chunk_index), []).append(ref)
        return chunks

    def _data_transformers(self, blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        transformers = []
        for function, features in self.function_features.items():
            ops = sorted(features["transform_ops"])
            if not ops:
                continue
            input_sources = sources_for_function(function, blobs, self.large_copies)
            strong_transform_api = any(
                op in {"base64", "hex", "gzip", "zlib", "aes", "rc4", "chacha20", "bytes_to_string"}
                for op in ops
            )
            has_buffer_evidence = (
                features["byte_memory_ops"] >= 3
                or bool(features["large_copies"])
                or bool(input_sources)
                or strong_transform_api
            )
            if not has_buffer_evidence:
                continue
            if (
                not should_analyze_function(function, getattr(self, "ownership", {}))
                and not input_sources
                and not features["large_copies"]
                and not strong_transform_api
            ):
                continue

            score = 0
            if features["backward_jumps"]:
                score += 1
            if features["byte_memory_ops"] >= 3:
                score += 1
            if len(ops) >= 2:
                score += 1
            if any(op in {"base64", "hex", "gzip", "zlib", "aes", "rc4", "chacha20"} for op in ops):
                score += 2
            if features["large_copies"]:
                score += 1
            if score == 0:
                continue

            transformers.append(
                {
                    "function": function,
                    "operations": ops,
                    "loop_indicators": {
                        "backward_jumps": features["backward_jumps"],
                        "byte_memory_ops": features["byte_memory_ops"],
                    },
                    "input_sources": [],
                    "candidate_input_sources": input_sources,
                    "source_relationships": [
                        {"source_blob": source, "relationship": "function_references_blob",
                         "status": "candidate", "unresolved_reasons": ["blob_to_transform_argument_flow_not_verified"]}
                        for source in input_sources
                    ],
                    "large_copies": [large_copy_to_dict(copy) for copy in features["large_copies"]],
                    "confidence": confidence(score),
                }
            )
        propagate_transformer_sources(transformers, self.graph)
        return transformers

    def _loader_behaviors(
        self, transformers: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        loaders = []
        transformer_functions = {item["function"] for item in transformers}
        for function, features in self.function_features.items():
            hints = normalized_loader_hints(features)
            if features["magic_checks"] & {"MZ", "PE"}:
                hints.add("pe_header_parsing")
            if "ELF" in features["magic_checks"]:
                hints.add("elf_header_parsing")
            if not hints:
                continue

            called_transformers = sorted(
                call.target for call in self.graph.get(function, []) if call.target in transformer_functions
            )
            score = len(hints)
            if called_transformers:
                score += 1
            if bool(hints & {"pe_header_parsing", "elf_header_parsing"}) and "dynamic_import_resolution" in hints:
                score += 1
            if "raw_syscall" in hints and "executable_memory_requested" in hints:
                score += 1
            kind = classify_loader(hints)
            if not should_promote_loader(kind, hints, features, called_transformers, transformers):
                continue

            loaders.append(
                {
                    "function": function,
                    "kind": kind,
                    "confidence": "low" if kind.endswith("_candidate") else confidence(score),
                    "relationship_status": "candidate" if kind.endswith("_candidate") else "observation",
                    "evidence_scope": "function_cooccurrence",
                    "unresolved_reasons": [
                        "image_or_buffer_to_mapping_flow_not_verified",
                        "mapped_buffer_to_control_transfer_flow_not_verified",
                    ] if kind.endswith("_candidate") else [],
                    "evidence": sorted(hints),
                    "called_transformers": called_transformers,
                    "allocation_constants": sorted(features["allocation_constants"]),
                    "protection_constants": sorted(features["protection_constants"]),
                    "memory_operations": features.get("memory_operations", []),
                }
            )
        component_loader = self._component_loader_behavior(loaders, transformers)
        if component_loader is not None:
            loaders.insert(0, component_loader)
        return loaders

    def _component_loader_behavior(
        self, loaders: list[dict[str, Any]], transformers: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        # Reachable-function unions do not establish shared buffers or execution order.
        return None

    def _embedded_artifacts(
        self,
        blobs: list[dict[str, Any]],
        transformers: list[dict[str, Any]],
        loaders: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        artifacts = []
        for blob in blobs:
            reasons = set(blob.get("reasons") or [])
            magic = {item.get("magic") for item in blob.get("magic_offsets") or []}
            referenced_by = set(blob.get("referenced_by") or [])
            related_transformers = [
                item["function"] for item in transformers
                if blob["id"] in item.get("candidate_input_sources", [])
            ]
            has_large_copy = "large_copy_source" in reasons
            has_executable_magic = bool(magic & {"MZ", "PE", "ELF"})
            has_archive_magic = bool(magic & {"PK", "gzip", "zlib"})
            if not referenced_by and not has_large_copy:
                continue
            if not (has_large_copy or has_executable_magic or has_archive_magic
                    or blob["entropy"] >= HIGH_ENTROPY_THRESHOLD):
                continue
            candidate_loaders = []
            for loader in loaders:
                function = loader["function"]
                if function == "<reachable_component>":
                    continue
                bases = []
                if function in referenced_by:
                    bases.append("loader_candidate_function_references_blob")
                if set(loader.get("called_transformers") or []) & set(related_transformers):
                    bases.append("calls_transformer_with_candidate_blob_reference")
                if bases:
                    candidate_loaders.append({
                        "function": function,
                        "relationship": "possible_blob_use",
                        "status": "candidate",
                        "evidence": bases,
                        "unresolved_reasons": ["blob_to_loader_argument_flow_not_verified"],
                    })
            artifacts.append({
                "kind": "embedded_static_artifact",
                "confidence": "medium",
                "source_blob": blob["id"],
                "source": {"section": blob["section"], "va": blob["va"],
                           "size": blob["size"], "entropy": blob["entropy"]},
                "referenced_by": sorted(referenced_by),
                # Reserved for verified data-flow relationships.
                "transformers": [],
                "loaders": [],
                "candidate_transformers": related_transformers,
                "candidate_loader_relationships": candidate_loaders,
                "relationship_status": "unresolved",
                "unresolved_reasons": ["transformation_of_blob_not_verified", "loading_or_execution_of_blob_not_verified"],
                "evidence": ["static data region identified"]
                + (["blob has executable file magic"] if has_executable_magic else [])
                + (["blob has archive file magic"] if has_archive_magic else [])
                + (["blob is copied in a large contiguous transfer"] if has_large_copy else [])
                + (["blob has high entropy"] if blob["entropy"] >= HIGH_ENTROPY_THRESHOLD else []),
            })
        return artifacts


def analyze_semantics(analyzer: Any, graph: dict[str, list[Any]]) -> dict[str, Any]:
    pass_timings = []
    pass_errors = []
    total_started = time.monotonic()

    def timed(name: str, callback, default=None):
        started = time.monotonic()
        try:
            value = callback()
            pass_timings.append(
                {"name": name, "duration_seconds": round(time.monotonic() - started, 3)}
            )
            return value
        except Exception as exc:
            pass_errors.append(
                {
                    "name": name,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
            )
            pass_timings.append(
                {
                    "name": name,
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "failed": True,
                    "error_type": type(exc).__name__,
                }
            )
            return default() if callable(default) else default

    semantics = timed(
        "semantic_scanner",
        lambda: SemanticScanner(analyzer, graph).analyze(),
        default={"assessment_hints": []},
    )

    from gobbler.passes.behavior_graph import build_behavior_graph
    from gobbler.passes.behavior_ir import build_behavior_ir
    from gobbler.passes.behavior_story import build_behavior_story
    from gobbler.passes.artifact_classifier import analyze_artifacts
    from gobbler.passes.cfg import analyze_cfg
    from gobbler.passes.constants import analyze_constants
    from gobbler.passes.dataflow import analyze_dataflow
    from gobbler.passes.decryption import analyze_decryption_recovery
    from gobbler.passes.go_types import analyze_go_types
    from gobbler.passes.indicator_consumers import attach_indicator_consumers
    from gobbler.passes.interesting import rank_interesting_functions
    from gobbler.passes.runtime_decoding import analyze_runtime_decoding
    from gobbler.passes.semantic_chains import build_semantic_chains
    from gobbler.passes.sink_args import analyze_sink_args

    global_constants, _arrays = timed(
        "constants",
        lambda: analyze_constants(analyzer, graph),
        default=(
            {"global_strings": [], "constant_arrays": [], "numeric_constants": []},
            [],
        ),
    )
    semantics["global_constants"] = global_constants
    semantics["dataflow"] = timed(
        "dataflow",
        lambda: analyze_dataflow(analyzer, graph, semantics),
        default={"functions": {}, "summary": {}},
    )
    semantics["cfg"] = timed("cfg", lambda: analyze_cfg(analyzer, graph), default={"functions": {}, "summary": {}})
    semantics["go_types"] = timed(
        "go_types",
        lambda: analyze_go_types(analyzer),
        default={"summary": {"available": False, "error": "pass_failed"}},
    )
    semantics["interesting_functions"] = timed(
        "interesting_functions",
        lambda: rank_interesting_functions(graph, semantics),
        default=[],
    )
    semantics["behavior_graph"] = timed(
        "behavior_graph",
        lambda: build_behavior_graph(graph, semantics),
        default={"nodes": [], "edges": [], "summary": {}},
    )
    semantics["behavior_ir"] = timed(
        "behavior_ir",
        lambda: build_behavior_ir(analyzer, graph, semantics),
        default={"summary": {}, "functions": {}},
    )
    semantics["semantic_chains"] = timed(
        "semantic_chains",
        lambda: build_semantic_chains(graph, semantics),
        default={"summary": {}, "chains": []},
    )
    semantics["runtime_decoding"] = timed(
        "runtime_decoding",
        lambda: analyze_runtime_decoding(analyzer, graph, semantics),
        default={"summary": {}, "functions": []},
    )
    semantics["decryption_recovery"] = timed(
        "decryption_recovery",
        lambda: analyze_decryption_recovery(analyzer, semantics),
        default={"summary": {}, "decoded_artifacts": [], "xor_recovered_artifacts": []},
    )
    semantics["artifact_classification"] = timed(
        "artifact_classification",
        lambda: analyze_artifacts(analyzer, semantics),
        default={"summary": {}, "notable_blobs": [], "embedded_artifacts": []},
    )
    semantics = timed(
        "indicator_consumers",
        lambda: attach_indicator_consumers(graph, semantics),
        default=lambda: semantics,
    )
    semantics["behavior_story"] = timed(
        "behavior_story",
        lambda: build_behavior_story(graph, semantics),
        default={"summary": {}, "narrative": [], "execution_flow": []},
    )
    semantics["sink_args"] = timed(
        "sink_args",
        lambda: analyze_sink_args(graph, semantics),
        default={"summary": {}, "sinks": []},
    )
    semantics["analysis_timing"] = {
        "total_seconds": round(time.monotonic() - total_started, 3),
        "passes": pass_timings,
    }
    if pass_errors:
        semantics["analysis_errors"] = pass_errors
        semantics.setdefault("assessment_hints", []).append(
            "One or more optional semantic enrichment passes failed; see analysis_errors."
        )
    if (semantics["runtime_decoding"].get("summary") or {}).get("likely_string_decoder_count"):
        semantics.setdefault("assessment_hints", []).append(
            "Reachable code contains functions that decode or transform bytes and materialize Go strings at runtime."
        )
    return semantics


def rip_target(insn, operand) -> int:
    return x86_rip_target(insn, operand)


def canonical_register(reg_id: int) -> str | None:
    return canonical_x86_register(reg_id)


def operand_text(insn) -> str:
    return insn.op_str


def indirect_call_kind(operand) -> str:
    if operand.type == X86_OP_REG:
        return "register_call"
    if operand.type == X86_OP_MEM:
        return "memory_call"
    return "other_indirect_call"


def update_register_provenance(
    insn, register_provenance: dict[str, dict[str, Any]], arch: str
) -> None:
    if len(insn.operands) < 2 or insn.operands[0].type != X86_OP_REG:
        return
    dest = canonical_register(insn.operands[0].reg)
    if dest is None:
        return
    src = insn.operands[1]
    if src.type == X86_OP_REG:
        src_reg = canonical_register(src.reg)
        if src_reg and src_reg in register_provenance:
            register_provenance[dest] = {
                **register_provenance[src_reg],
                "via_register": src_reg,
            }
        else:
            register_provenance[dest] = {
                "kind": "register_value",
                "register": src_reg or insn.reg_name(src.reg),
                "instruction": hex(insn.address),
            }
        return
    if src.type == X86_OP_IMM:
        register_provenance[dest] = {
            "kind": "immediate",
            "value": hex(int(src.imm)),
            "instruction": hex(insn.address),
        }
        return
    if src.type == X86_OP_MEM:
        register_provenance[dest] = memory_provenance(insn, src, arch)
        return
    register_provenance.pop(dest, None)


def memory_provenance(insn, operand, arch: str) -> dict[str, Any]:
    mem = operand.mem
    base = canonical_register(mem.base) if mem.base else None
    index = canonical_register(mem.index) if mem.index else None
    provenance: dict[str, Any] = {
        "kind": "memory_load",
        "instruction": hex(insn.address),
        "base": base,
        "index": index,
        "scale": mem.scale,
        "disp": hex(mem.disp) if mem.disp else None,
    }
    concrete_target = memory_target(insn, operand, arch)
    if concrete_target is not None:
        provenance["memory_kind"] = "rip_relative_global" if mem.base == X86_REG_RIP else "absolute_global"
        provenance["address"] = hex(concrete_target)
    elif base in {"RSP", "RBP"}:
        provenance["memory_kind"] = "stack"
    elif index is not None:
        provenance["memory_kind"] = "indexed_table"
    elif base is not None:
        provenance["memory_kind"] = "register_indirect"
    else:
        provenance["memory_kind"] = "absolute_or_unknown"
    return provenance


def indirect_call_provenance(
    operand, register_provenance: dict[str, dict[str, Any]], arch: str
) -> dict[str, Any] | None:
    if operand.type == X86_OP_REG:
        reg = canonical_register(operand.reg)
        if reg is None:
            return {"kind": "unknown_register", "register": None}
        return register_provenance.get(reg, {"kind": "unknown_register", "register": reg})
    if operand.type == X86_OP_MEM:
        return memory_operand_provenance(operand, arch)
    return None


def memory_operand_provenance(operand, arch: str) -> dict[str, Any]:
    mem = operand.mem
    base = canonical_register(mem.base) if mem.base else None
    index = canonical_register(mem.index) if mem.index else None
    provenance: dict[str, Any] = {
        "kind": "memory_target",
        "base": base,
        "index": index,
        "scale": mem.scale,
        "disp": hex(mem.disp) if mem.disp else None,
    }
    concrete_target = int(mem.disp) if arch == "x86" and not mem.base and not mem.index and mem.disp else None
    if concrete_target is not None:
        provenance["memory_kind"] = "absolute_global"
        provenance["address"] = hex(concrete_target)
    elif base in {"RSP", "RBP"}:
        provenance["memory_kind"] = "stack"
    elif index is not None:
        provenance["memory_kind"] = "indexed_table"
    elif base is not None:
        provenance["memory_kind"] = "register_indirect"
    else:
        provenance["memory_kind"] = "absolute_or_unknown"
    return provenance


def classify_indirect_call(
    operand, provenance: dict[str, Any] | None
) -> tuple[str, list[str]]:
    evidence = []
    if operand.type == X86_OP_REG:
        reg = canonical_register(operand.reg) or "unknown"
        evidence.append(f"target comes from register {reg}")
    elif operand.type == X86_OP_MEM:
        evidence.append("target is read from memory")

    if not provenance:
        return "unresolved_indirect_call", evidence

    kind = provenance.get("kind")
    memory_kind = provenance.get("memory_kind")
    if kind == "call_return":
        call = provenance.get("call", "")
        evidence.append(f"target register derives from return value of {call}")
        if any(name in call for name in ("GetProcAddress", "LoadLibrary", "LazyProc", "Syscall")):
            return "dynamic_api_function_pointer", evidence
        if any(name in call for name in ("VirtualAlloc", "mmap", "MapViewOfFile")):
            return "runtime_allocated_code_pointer", evidence
        return "call_return_function_pointer", evidence

    if memory_kind == "stack":
        evidence.append("target is loaded from stack memory")
        return "stack_closure_or_defer_call", evidence
    if memory_kind == "rip_relative_global":
        evidence.append("target derives from RIP-relative global memory")
        return "global_function_pointer_or_dispatch_table", evidence
    if memory_kind == "absolute_global":
        evidence.append("target derives from absolute global memory")
        return "global_function_pointer_or_dispatch_table", evidence
    if memory_kind == "indexed_table":
        evidence.append("target uses indexed memory addressing")
        return "dispatch_table_or_interface_call", evidence
    if memory_kind == "register_indirect":
        evidence.append("target uses register-indirect memory addressing")
        return "interface_method_or_object_dispatch", evidence
    if kind == "immediate":
        evidence.append("target register was loaded from an immediate value")
        return "computed_or_obfuscated_direct_pointer", evidence

    return "unresolved_indirect_call", evidence


def indirect_call_to_dict(call: IndirectCall) -> dict[str, Any]:
    return {
        "function": call.function,
        "address": hex(call.instruction),
        "operand": call.operand,
        "kind": call.call_kind,
        "classification": call.classification,
        "evidence": call.evidence,
        "provenance": call.provenance,
        "display": f"{call.function}:{hex(call.instruction)} call {call.operand} [{call.classification}]",
    }


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


def is_backward_jump(insn) -> bool:
    if not insn.group(X86_GRP_JUMP):
        return False
    if not insn.operands or insn.operands[0].type != X86_OP_IMM:
        return False
    return int(insn.operands[0].imm) < insn.address


def is_control_transfer(insn) -> bool:
    mnemonic = insn.mnemonic.lower()
    return mnemonic == "call" or insn.group(X86_GRP_JUMP)


def transfer_type(insn) -> str:
    if insn.mnemonic.lower() == "call":
        return "call"
    if insn.mnemonic.lower() == "jmp":
        return "jmp"
    return "conditional_jump"


def mid_function_transfer_to_dict(transfer: MidFunctionTransfer) -> dict[str, Any]:
    classification = "internal_branch"
    if not transfer.is_internal_branch:
        classification = "mid_function_call" if transfer.transfer_type == "call" else "inter_function_mid_jump"
    if transfer.target_function.startswith("runtime.duff"):
        classification = "go_runtime_duff_helper"
    elif transfer.target_function.startswith("runtime.") and not transfer.is_internal_branch:
        classification = "go_runtime_mid_function_helper"

    return {
        "source_function": transfer.source_function,
        "instruction": hex(transfer.instruction),
        "mnemonic": transfer.mnemonic,
        "transfer_type": transfer.transfer_type,
        "target_address": hex(transfer.target),
        "target_function": transfer.target_function,
        "target_kind": transfer.target_kind,
        "target_offset": hex(transfer.target_offset),
        "is_internal_branch": transfer.is_internal_branch,
        "classification": classification,
        "display": f"{transfer.source_function}:{hex(transfer.instruction)} {transfer.mnemonic} -> {transfer.target_function}+0x{transfer.target_offset:x}",
    }


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


def coalesce_blob_runs(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not blobs:
        return blobs
    blobs = dedupe_blob_spans(blobs)
    blobs = sorted(blobs, key=lambda blob: (blob["section"], int(blob["va"], 16)))
    result = []
    current = dict(blobs[0])
    for blob in blobs[1:]:
        current_end = int(current["va"], 16) + int(current["size"], 16)
        if blob["section"] == current["section"] and int(blob["va"], 16) == current_end:
            current["size"] = hex(int(current["size"], 16) + int(blob["size"], 16))
            current["entropy"] = round(max(current["entropy"], blob["entropy"]), 3)
            current["reference_count"] += blob["reference_count"]
            current["referenced_by"] = sorted(set(current["referenced_by"]) | set(blob["referenced_by"]))
            current["magic_offsets"].extend(blob["magic_offsets"])
            current["reasons"] = sorted(set(current["reasons"]) | set(blob["reasons"]))
            continue
        result.append(current)
        current = dict(blob)
    result.append(current)
    for index, blob in enumerate(result):
        blob["id"] = f"blob_{index}"
    return result


def dedupe_blob_spans(blobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for blob in blobs:
        key = (blob["section"], blob["va"], blob["size"])
        if key not in deduped:
            item = dict(blob)
            item["referenced_by"] = sorted(set(item.get("referenced_by") or []))
            item["reasons"] = sorted(set(item.get("reasons") or []))
            item["magic_offsets"] = unique_magic_offsets(item.get("magic_offsets") or [])
            item["duplicate_count"] = 1
            deduped[key] = item
            continue
        item = deduped[key]
        item["entropy"] = round(max(item.get("entropy", 0), blob.get("entropy", 0)), 3)
        item["reference_count"] = item.get("reference_count", 0) + blob.get("reference_count", 0)
        item["referenced_by"] = sorted(
            set(item.get("referenced_by") or []) | set(blob.get("referenced_by") or [])
        )
        item["reasons"] = sorted(set(item.get("reasons") or []) | set(blob.get("reasons") or []))
        item["magic_offsets"] = unique_magic_offsets(
            (item.get("magic_offsets") or []) + (blob.get("magic_offsets") or [])
        )
        item["duplicate_count"] = item.get("duplicate_count", 1) + 1
    return list(deduped.values())


def unique_magic_offsets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = (item.get("offset"), item.get("magic"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result[:16]


def is_excluded_data_section(name: str) -> bool:
    lowered = name.lower()
    return lowered in {
        ".text",
        ".pdata",
        ".xdata",
        ".reloc",
        ".idata",
        ".symtab",
        ".bss",
        ".noptrbss",
        ".noptrdata",
        ".gopclntab",
    } or lowered.startswith(".debug")


def ranges_overlap(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def range_containing_va(
    ranges: list[dict[str, Any]], starts: list[int], va: int
) -> dict[str, Any] | None:
    index = bisect_right(starts, va) - 1
    if index < 0:
        return None
    function = ranges[index]
    if function["Start"] <= va < function["End"]:
        return function
    return None


def sources_for_function(
    function: str, blobs: list[dict[str, Any]], large_copies: list[LargeCopy]
) -> list[str]:
    sources = set()
    for blob in blobs:
        if function in blob["referenced_by"]:
            sources.add(blob["id"])
    for copy in large_copies:
        if copy.function != function or copy.source is None:
            continue
        for blob in blobs:
            start = int(blob["va"], 16)
            end = start + int(blob["size"], 16)
            if start <= copy.source < end:
                sources.add(blob["id"])
    return sorted(sources)


def propagate_transformer_sources(
    transformers: list[dict[str, Any]], graph: dict[str, list[Any]]
) -> None:
    by_function = {item["function"]: item for item in transformers}
    # Snapshot direct references so iteration never fabricates transitive flow.
    direct_sources = {name: list(item.get("candidate_input_sources") or [])
                      for name, item in by_function.items()}
    for caller, calls in graph.items():
        for call in calls:
            callee_item = by_function.get(call.target)
            if callee_item is None:
                continue
            for source in direct_sources.get(caller, []):
                candidates = callee_item.setdefault("candidate_input_sources", [])
                if source not in candidates:
                    candidates.append(source)
                callee_item.setdefault("source_relationships", []).append({
                    "source_blob": source, "relationship": "caller_references_blob",
                    "caller": caller, "status": "candidate",
                    "unresolved_reasons": ["call_argument_buffer_flow_not_verified"],
                })


def large_copy_to_dict(copy: LargeCopy) -> dict[str, Any]:
    return {
        "instruction": hex(copy.instruction),
        "source": hex(copy.source) if copy.source is not None else None,
        "size": hex(copy.size) if copy.size is not None else None,
        "mnemonic": copy.mnemonic,
    }


def confidence(score: int) -> str:
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def memory_api_spec(target: str) -> tuple[str, str, int] | None:
    """Known Go signatures: (operation, protection convention, ABI word index)."""
    name = target.removesuffix(".abi0")
    for prefix in ("syscall.", "golang.org/x/sys/unix.", "unix."):
        if name == prefix + "Mmap":
            return "memory_allocation", "unix", 3
        if name == prefix + "(*mmapper).Mmap":
            # Inlined public Mmap wrappers expose the internal receiver argument.
            return "memory_allocation", "unix", 4
        if name == prefix + "Mprotect":
            # A Go slice occupies three argument words.
            return "memory_protection_change", "unix", 3
    for prefix in ("golang.org/x/sys/windows.", "windows."):
        if name == prefix + "VirtualAlloc":
            return "memory_allocation", "windows", 3
        if name == prefix + "VirtualProtect":
            return "memory_protection_change", "windows", 2
    # A resolved native name alone does not identify the calling convention.
    if name in {"VirtualAlloc", "VirtualProtect", "mmap", "mprotect"}:
        kind = "memory_protection_change" if name in {"VirtualProtect", "mprotect"} else "memory_allocation"
        return kind, "unknown", 0
    return None


def memory_protection_status(value: int | None, convention: str, goos: str) -> str:
    if value is None:
        return "unknown"
    if convention == "windows" and goos == "windows":
        base = value & 0xFF
        if base in EXECUTE_PROTECTIONS:
            return "executable"
        if base in {0x01, 0x02, 0x04, 0x08}:
            return "non_executable"
    if convention == "unix" and goos == "linux":
        # Linux PROT_EXEC=4; allow PROT_GROWSDOWN/PROT_GROWSUP modifiers.
        if value >= 0 and not value & ~0x03000007:
            return "executable" if value & 4 else "non_executable"
    return "unknown"


def memory_argument_location(analyzer: Any, target: str, spec: tuple[str, str, int]) -> str | int | None:
    """Return a register or pre-call SP offset only for a known Go ABI."""
    _kind, convention, index = spec
    arch = analyzer.binary_view.arch
    if convention == "unknown" or arch not in {"x86", "x86_64"}:
        return None
    if arch == "x86":
        # Mmap's offset is int64, occupying two stack words on 386.
        return (index + 1) * 4 if target.removesuffix(".abi0").endswith(".Mmap") else index * 4
    goresym = getattr(analyzer, "goresym", {}) or {}
    build_info = goresym.get("BuildInfo") or {}
    version = str(goresym.get("Version") or build_info.get("GoVersion") or "")
    match = re.fullmatch(r"(?:go)?1\.(\d+)(?:[.\w-]*)", version)
    if target.endswith(".abi0"):
        return index * 8
    if match is None:
        return None
    settings = build_info.get("Settings") or []
    experiment = next(
        (str(item.get("Value", "")) for item in settings if isinstance(item, dict) and item.get("Key") == "GOEXPERIMENT"),
        "",
    )
    if int(match.group(1)) < 17 or {"noregabi", "noregabiargs"} & set(experiment.split(",")):
        return index * 8
    return ("RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11")[index]


def recover_memory_operations(
    analyzer: Any, function_name: str, function: dict[str, Any], calls: list[Any]
) -> list[dict[str, Any]]:
    """Conservative constant recovery within a single basic block.

    Never reuse values across calls, branches, or merge points. Unsupported
    instructions invalidate written registers; unresolved/dynamic APIs stay
    unknown instead of borrowing constants from another call or function.
    """
    candidates = {call.address: (call, memory_api_spec(call.target)) for call in calls if memory_api_spec(call.target)}
    if not candidates:
        return []
    instructions = list(analyzer.function_content(function))
    branch_targets = {
        int(insn.operands[0].imm)
        for insn in instructions
        if insn.mnemonic.startswith(("j", "loop")) and insn.operands and insn.operands[0].type == X86_OP_IMM
    }
    registers: dict[str, int] = {}
    stack: dict[int, tuple[int, int]] = {}
    operations = []
    goos = str((getattr(analyzer, "goresym", {}) or {}).get("OS", "")).lower()
    for insn in instructions:
        if insn.address in branch_targets:
            registers.clear()
            stack.clear()
        mnemonic = insn.mnemonic.lower()
        if insn.address in candidates:
            call, spec = candidates[insn.address]
            location = memory_argument_location(analyzer, call.target, spec)
            direct = mnemonic == "call" and insn.operands and insn.operands[0].type == X86_OP_IMM and not getattr(call, "via", None)
            value = None
            if direct and isinstance(location, str):
                value = registers.get(location)
            elif direct and isinstance(location, int):
                stored = stack.get(location)
                if stored and stored[0] >= (4 if analyzer.binary_view.arch == "x86" or spec[1] == "windows" else 8):
                    value = stored[1]
            protection = {
                "status": memory_protection_status(value, spec[1], goos),
                "recovery_method": "basic_block_constant" if value is not None else "unresolved",
            }
            if location is not None:
                protection["argument_location"] = location if isinstance(location, str) else f"SP+{hex(location)}"
            if value is not None:
                protection["value"] = value
            if protection["status"] == "unknown":
                protection["reason"] = "unresolved_argument_or_unsupported_abi" if value is None else "unsupported_protection_value_or_os"
            operations.append({
                "function": function_name,
                "address": hex(insn.address),
                "target_api": call.target,
                "kind": spec[0],
                "memory_protection": protection,
            })
        if mnemonic == "call" or mnemonic.startswith(("j", "ret", "loop")):
            registers.clear()
            stack.clear()
            continue

        operands = insn.operands
        value = None
        if len(operands) >= 2 and mnemonic in {"mov", "movabs"}:
            source = operands[1]
            if source.type == X86_OP_IMM:
                value = int(source.imm)
            elif source.type == X86_OP_REG and source.size >= 4:
                value = registers.get(canonical_register(source.reg))
        elif len(operands) == 2 and mnemonic == "xor" and operands[0].type == operands[1].type == X86_OP_REG and operands[0].reg == operands[1].reg:
            value = 0
        try:
            _reads, writes = insn.regs_access()
        except (AttributeError, ValueError):
            registers.clear()
            stack.clear()
            continue
        for register in writes:
            name = canonical_register(register)
            registers.pop(name, None)
            if name == "RSP":
                stack.clear()
        if not operands:
            continue
        dest = operands[0]
        if dest.type == X86_OP_REG and dest.size >= 4 and value is not None:
            registers[canonical_register(dest.reg)] = value & ((1 << (dest.size * 8)) - 1)
        for operand in operands:
            if operand.type != X86_OP_MEM or not operand.access & 2:
                continue
            if canonical_register(operand.mem.base) == "RSP" and not operand.mem.index:
                offset = int(operand.mem.disp)
                for old_offset, (size, _value) in list(stack.items()):
                    if old_offset < offset + operand.size and offset < old_offset + size:
                        del stack[old_offset]
                if operand is dest and value is not None and dest.size >= 4:
                    stack[offset] = (dest.size, value & ((1 << (dest.size * 8)) - 1))
            else:
                stack.clear()
    return operations


def normalized_loader_hints(features: dict[str, Any]) -> set[str]:
    hints = set(features["loader_hints"])
    # Function-wide constants and API names do not establish call arguments.
    hints.discard("executable_memory_requested")
    if "executable_memory_allocation" in hints:
        hints.remove("executable_memory_allocation")
        hints.add("memory_allocation")
    if any(
        operation.get("memory_protection", {}).get("status") == "executable"
        for operation in features.get("memory_operations", [])
    ):
        hints.add("executable_memory_requested")
    return hints


def should_promote_loader(
    kind: str,
    hints: set[str],
    features: dict[str, Any],
    called_transformers: list[str],
    transformers: list[dict[str, Any]],
) -> bool:
    # Keep neutral observations even when no loading hypothesis is justified.
    return bool(hints & {
        "pe_header_parsing", "elf_header_parsing", "dynamic_import_resolution",
        "dynamic_library_load", "executable_memory_requested", "memory_allocation",
        "memory_protection_change", "thread_creation", "raw_syscall", "dynamic_syscall_call",
    })


def classify_loader(hints: set[str]) -> str:
    if "pe_header_parsing" in hints and "dynamic_import_resolution" in hints:
        return "pe_loader_candidate"
    if "elf_header_parsing" in hints and "dynamic_import_resolution" in hints:
        return "elf_loader_candidate"
    if "executable_memory_requested" in hints and (
        "dynamic_import_resolution" in hints
        or "thread_creation" in hints
        or "pe_header_parsing" in hints
        or "elf_header_parsing" in hints
    ):
        return "dynamic_code_loader_candidate"
    if "dynamic_import_resolution" in hints or "dynamic_library_load" in hints:
        return "dynamic_api_resolution"
    if "pe_header_parsing" in hints:
        return "pe_header_parsing"
    if "elf_header_parsing" in hints:
        return "elf_header_parsing"
    if "executable_memory_requested" in hints:
        return "executable_memory_request"
    if "memory_protection_change" in hints:
        return "memory_protection_change"
    if "memory_allocation" in hints:
        return "memory_allocation"
    if "raw_syscall" in hints:
        return "native_api_usage"
    return "runtime_behavior_pattern"


def describe_allocation_type(value: int) -> str:
    parts = [name for bit, name in ALLOCATION_TYPES.items() if value & bit]
    return "|".join(parts) if parts else hex(value)


def pe_imports(binary: lief.Binary) -> dict[str, list[str]]:
    if not hasattr(binary, "imports"):
        return {}
    imports = getattr(binary, "imports", None)
    if imports is None:
        return {}
    result: dict[str, list[str]] = {}
    for imported_library in imports:
        entries = []
        for entry in imported_library.entries:
            if entry.name:
                entries.append(entry.name)
            elif entry.is_ordinal:
                entries.append(f"ordinal_{entry.ordinal}")
        result[imported_library.name] = sorted(entries)
    return result


def assessment_hints(
    blobs: list[dict[str, Any]],
    transformers: list[dict[str, Any]],
    loaders: list[dict[str, Any]],
    payloads: list[dict[str, Any]],
    mid_function_transfers: list[dict[str, Any]],
    indirect_calls: list[dict[str, Any]],
) -> list[str]:
    hints = []
    if any(
        transfer["classification"] not in {"go_runtime_duff_helper", "internal_branch"}
        for transfer in mid_function_transfers
    ):
        hints.append("Reachable code transfers control into the middle of another known function, which may indicate helper stubs, tail jumps, or obfuscation.")
    if blobs:
        hints.append("Reachable code references high-entropy, magic-containing, or large-copy static data regions.")
    if any(
        call["classification"]
        in {
            "dynamic_api_function_pointer",
            "runtime_allocated_code_pointer",
            "computed_or_obfuscated_direct_pointer",
        }
        for call in indirect_calls
    ):
        hints.append("Reachable code contains indirect calls through computed or dynamically sourced function pointers.")
    if transformers:
        hints.append("Reachable functions contain byte transformation loops that may encode/decode data or generate/fill buffers at runtime.")
    if any(loader["kind"] == "pe_loader_candidate" for loader in loaders):
        hints.append("PE-header and dynamic-API hints co-occur; reflective loading and buffer flow are not verified.")
    elif any(loader["kind"] == "elf_loader_candidate" for loader in loaders):
        hints.append("ELF-header and dynamic-API hints co-occur; loading and buffer flow are not verified.")
    elif any(loader["kind"] == "dynamic_code_loader_candidate" for loader in loaders):
        hints.append("Executable-memory and dynamic-API hints co-occur; loading and control transfer are not verified.")
    if payloads:
        hints.append("Embedded static artifacts were identified; their transformation, loading, and execution are not verified.")
    return hints
