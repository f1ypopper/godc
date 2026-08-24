import hashlib
import math
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

import lief
from capstone.x86 import *

from gobbler.arch import canonical_register as canonical_x86_register
from gobbler.arch import memory_target, memory_target_access, rip_target as x86_rip_target
from gobbler.binary import BinarySection


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
    "syscall.GetProcAddress": "dynamic_import_resolution",
    "syscall.(*LazyProc).Find": "dynamic_import_resolution",
    "syscall.(*LazyProc).Call": "dynamic_syscall_call",
    "syscall.Syscall": "raw_syscall",
    "syscall.SyscallN": "raw_syscall",
    "syscall.Mmap": "executable_memory_allocation",
    "syscall.Mprotect": "memory_protection_change",
    "golang.org/x/sys/unix.Mmap": "executable_memory_allocation",
    "golang.org/x/sys/unix.Mprotect": "memory_protection_change",
    "unix.Mmap": "executable_memory_allocation",
    "unix.Mprotect": "memory_protection_change",
    "syscall.Exec": "process_execution",
    "syscall.ForkExec": "process_execution",
    "os/exec.Command": "process_execution",
    "os/exec.(*Cmd).Start": "process_execution",
    "os/exec.(*Cmd).Run": "process_execution",
    "dlopen": "dynamic_library_load",
    "dlsym": "dynamic_import_resolution",
    "VirtualAlloc": "executable_memory_allocation",
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
    data_references: list[DataReference] = field(default_factory=list)
    large_copies: list[LargeCopy] = field(default_factory=list)
    mid_function_transfers: list[MidFunctionTransfer] = field(default_factory=list)
    indirect_calls: list[IndirectCall] = field(default_factory=list)
    function_features: dict[str, dict[str, Any]] = field(default_factory=dict)
    sub_timings: list[dict[str, Any]] = field(default_factory=list)
    user_range_starts: list[int] = field(init=False)
    std_range_starts: list[int] = field(init=False)

    def __post_init__(self) -> None:
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
            "imports": self.analyzer.binary_view.imports(),
            "pe_imports": pe_imports(self.analyzer.binary),
            "mid_function_control_transfers": mid_function_transfers,
            "indirect_calls": indirect_calls,
            "notable_data_blobs": blobs,
            "data_transformers": transformers,
            "loader_behaviors": loaders,
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
        for copy in self.large_copies:
            if copy.source is None or copy.size is None:
                continue
            section = self._section_for_va(copy.source)
            if section is None or is_excluded_data_section(section.name):
                continue
            offset = copy.source - section.va
            size = min(copy.size, section.end - copy.source)
            if size < MIN_BLOB_SIZE:
                continue
            data = section.data[offset : offset + min(size, ENTROPY_SAMPLE_LIMIT)]
            entropy_sample = data[: min(len(data), ENTROPY_SAMPLE_LIMIT)]
            blobs.append(
                {
                    "id": f"blob_{len(blobs)}",
                    "section": section.name,
                    "va": hex(copy.source),
                    "size": hex(size),
                    "entropy": round(shannon_entropy(entropy_sample), 3),
                    "entropy_sampled": size > len(entropy_sample),
                    "sha256_prefix": hashlib.sha256(data).hexdigest()[:16],
                    "referenced_by": [copy.function],
                    "reference_count": 1,
                    "magic_offsets": magic_offsets(data[: min(len(data), 0x20000)])[:8],
                    "reasons": ["large_copy_source"],
                }
            )
        return blobs

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
                is_library_function(function)
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
                    "input_sources": input_sources,
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
                    "confidence": confidence(score),
                    "evidence": sorted(hints),
                    "called_transformers": called_transformers,
                    "allocation_constants": sorted(features["allocation_constants"]),
                    "protection_constants": sorted(features["protection_constants"]),
                }
            )
        component_loader = self._component_loader_behavior(loaders, transformers)
        if component_loader is not None:
            loaders.insert(0, component_loader)
        return loaders

    def _component_loader_behavior(
        self, loaders: list[dict[str, Any]], transformers: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        evidence = set()
        functions = set()
        for loader in loaders:
            evidence.update(loader["evidence"])
            functions.add(loader["function"])
        if not evidence:
            return None

        if {
            "pe_header_parsing",
            "dynamic_import_resolution",
        }.issubset(evidence) and (
            "dynamic_syscall_call" in evidence or "executable_memory_requested" in evidence
        ):
            kind = "reflective_pe_loader"
        elif {
            "elf_header_parsing",
            "dynamic_import_resolution",
        }.issubset(evidence) and (
            "dynamic_syscall_call" in evidence or "executable_memory_requested" in evidence
        ):
            kind = "reflective_elf_loader"
        elif "executable_memory_requested" in evidence and (
            "dynamic_import_resolution" in evidence or "thread_creation" in evidence
        ):
            kind = "dynamic_code_loader"
        else:
            return None

        return {
            "function": "<reachable_component>",
            "kind": kind,
            "confidence": "high",
            "evidence": sorted(evidence),
            "functions": sorted(functions),
            "called_transformers": sorted({item["function"] for item in transformers if item["input_sources"]}),
            "allocation_constants": sorted(
                {
                    value
                    for loader in loaders
                    for value in loader.get("allocation_constants", [])
                }
            ),
            "protection_constants": sorted(
                {
                    value
                    for loader in loaders
                    for value in loader.get("protection_constants", [])
                }
            ),
        }

    def _embedded_artifacts(
        self,
        blobs: list[dict[str, Any]],
        transformers: list[dict[str, Any]],
        loaders: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        artifacts = []
        if not blobs or not loaders:
            return artifacts
        reflective_loaders = [
            loader for loader in loaders if loader["kind"] in {"reflective_pe_loader", "reflective_elf_loader", "dynamic_code_loader"}
        ]
        if not reflective_loaders:
            return artifacts

        for blob in blobs[:8]:
            reasons = set(blob.get("reasons") or [])
            magic = {item.get("magic") for item in blob.get("magic_offsets") or []}
            related_transformers = [
                item["function"] for item in transformers if blob["id"] in item.get("input_sources", [])
            ]
            has_large_copy = "large_copy_source" in reasons
            has_executable_magic = bool(magic & {"MZ", "PE", "ELF"})
            has_archive_magic = bool(magic & {"PK", "gzip", "zlib"})
            has_transformer_consumer = bool(related_transformers)
            if not blob["referenced_by"] and not has_large_copy:
                continue
            if blob["entropy"] < HIGH_ENTROPY_THRESHOLD and not has_large_copy and not has_executable_magic:
                continue
            if not (
                has_large_copy
                or has_executable_magic
                or (has_archive_magic and has_transformer_consumer)
                or loader_consumes_transformer(reflective_loaders, related_transformers)
            ):
                continue
            artifacts.append(
                {
                    "kind": "encoded_or_encrypted_embedded_artifact",
                    "confidence": embedded_artifact_confidence(has_executable_magic, has_large_copy, related_transformers),
                    "source_blob": blob["id"],
                    "source": {
                        "section": blob["section"],
                        "va": blob["va"],
                        "size": blob["size"],
                        "entropy": blob["entropy"],
                    },
                    "transformers": related_transformers,
                    "loaders": [item["function"] for item in reflective_loaders],
                    "evidence": [
                        "static data blob is connected to loader-relevant behavior",
                    ]
                    + (["blob has executable file magic"] if has_executable_magic else [])
                    + (["blob is copied in a large contiguous transfer"] if has_large_copy else [])
                    + (["blob is consumed by byte transformation code"] if related_transformers else []),
                }
            )
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
    for caller, calls in graph.items():
        caller_item = by_function.get(caller)
        if caller_item is None or not caller_item["input_sources"]:
            continue
        for call in calls:
            callee_item = by_function.get(call.target)
            if callee_item is None or callee_item["input_sources"]:
                continue
            callee_item["input_sources"] = caller_item["input_sources"]
            callee_item["source_inference"] = f"called_by:{caller}"


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


def normalized_loader_hints(features: dict[str, Any]) -> set[str]:
    hints = set(features["loader_hints"])
    explicit_exec_api = bool(hints & {"executable_memory_allocation", "memory_protection_change"})
    syscall_exec_context = (
        bool(hints & {"raw_syscall", "dynamic_syscall_call"})
        and bool(features["allocation_constants"])
        and bool(features["protection_constants"])
        and bool(features["large_copies"])
    )
    if explicit_exec_api or syscall_exec_context:
        hints.add("executable_memory_requested")
    return hints


def should_promote_loader(
    kind: str,
    hints: set[str],
    features: dict[str, Any],
    called_transformers: list[str],
    transformers: list[dict[str, Any]],
) -> bool:
    if kind in {"reflective_pe_loader", "reflective_elf_loader", "dynamic_code_loader"}:
        return True
    if bool(hints & {"pe_header_parsing", "elf_header_parsing"}) and bool(hints & {"dynamic_import_resolution", "dynamic_syscall_call", "raw_syscall"}):
        return True
    transformer_by_function = {item["function"]: item for item in transformers}
    if called_transformers and any(
        transformer_by_function.get(function, {}).get("input_sources")
        for function in called_transformers
    ):
        return True
    return False


def loader_consumes_transformer(loaders: list[dict[str, Any]], transformers: list[str]) -> bool:
    transformer_set = set(transformers)
    if not transformer_set:
        return False
    return any(transformer_set & set(loader.get("called_transformers") or []) for loader in loaders)


def embedded_artifact_confidence(
    has_executable_magic: bool,
    has_large_copy: bool,
    related_transformers: list[str],
) -> str:
    score = int(has_executable_magic) + int(has_large_copy) + int(bool(related_transformers))
    return confidence(score + 1)


def classify_loader(hints: set[str]) -> str:
    if "pe_header_parsing" in hints and "dynamic_import_resolution" in hints:
        return "reflective_pe_loader"
    if "elf_header_parsing" in hints and "dynamic_import_resolution" in hints:
        return "reflective_elf_loader"
    if "executable_memory_requested" in hints and (
        "dynamic_import_resolution" in hints
        or "thread_creation" in hints
        or "pe_header_parsing" in hints
        or "elf_header_parsing" in hints
    ):
        return "dynamic_code_loader"
    if "dynamic_import_resolution" in hints or "dynamic_library_load" in hints:
        return "dynamic_api_resolution"
    if "raw_syscall" in hints:
        return "native_api_usage"
    return "runtime_behavior_pattern"


def is_library_function(function: str) -> bool:
    return function.startswith(
        (
            "github.com/lxn/",
            "golang.org/x/",
            "gopkg.in/",
            "internal/",
            "slices.",
            "syscall.",
            "runtime.",
            "reflect.",
            "sync.",
            "os.",
            "io.",
            "fmt.",
            "log.",
            "net/",
            "net.",
            "encoding/",
            "compress/",
            "crypto/",
            "path/",
            "strings.",
            "strconv.",
            "github.com/op/",
        )
    )


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
    if any(loader["kind"] == "reflective_pe_loader" for loader in loaders):
        hints.append("Reachable code parses PE headers and uses dynamic loading or executable-memory APIs.")
    elif any(loader["kind"] == "reflective_elf_loader" for loader in loaders):
        hints.append("Reachable code parses ELF headers and uses dynamic loading or executable-memory APIs.")
    elif any(loader["kind"] == "dynamic_code_loader" for loader in loaders):
        hints.append("Reachable code uses dynamic code allocation or execution-related APIs.")
    if payloads:
        hints.append("An embedded static artifact is connected to transformation and loader-relevant behavior.")
    return hints
