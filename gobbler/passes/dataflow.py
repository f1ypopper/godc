from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any

from capstone.x86 import *

from gobbler.arch import canonical_register as canonical_x86_register
from gobbler.arch import memory_target, rip_target as x86_rip_target
from gobbler.utils.noise import is_runtime_noise_call


ABI_INT_REGS = ("RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11")
STRING_ARG_REG_PAIRS = (("RAX", "RBX"), ("RCX", "RDI"), ("RSI", "R8"), ("R9", "R10"))
SLICE_ARG_REG_TRIPLES = (("RAX", "RBX", "RCX"), ("RDI", "RSI", "R8"), ("R9", "R10", "R11"))
MOV_LIKE = {"mov", "movabs", "lea"}


@dataclass(frozen=True)
class Value:
    kind: str
    label: str
    address: int | None = None
    value: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": self.kind,
            "label": self.label,
        }
        if self.address is not None:
            result["address"] = hex(self.address)
        if self.value is not None:
            result["value"] = self.value
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class MemorySlot:
    base: str
    disp: int

    def key(self) -> tuple[str, int]:
        return (self.base, self.disp)

    def to_dict(self) -> dict[str, Any]:
        return {"base": self.base, "disp": hex(self.disp)}


def analyze_dataflow(analyzer: Any, graph: dict[str, list[Any]], semantics: dict[str, Any]) -> dict[str, Any]:
    context = DataflowContext(analyzer, semantics)
    functions = {}
    for function_name in graph:
        function = context.function_by_name(function_name)
        if function is None:
            continue
        facts = FunctionDataflow(context, function_name, function).analyze()
        if has_interesting_facts(facts):
            functions[function_name] = facts
    return {
        "functions": functions,
        "summary": summarize_dataflow(functions),
    }


class DataflowContext:
    def __init__(self, analyzer: Any, semantics: dict[str, Any]):
        self.analyzer = analyzer
        self.semantics = semantics
        self.arrays = (semantics.get("global_constants") or {}).get("constant_arrays") or []
        self.strings = (semantics.get("global_constants") or {}).get("global_strings") or []
        self.blobs = semantics.get("notable_data_blobs") or []
        self.array_ranges = sorted(
            (int(array["va"], 16), int(array["va"], 16) + int(array["size"], 16), array)
            for array in self.arrays
        )
        self.array_starts = [start for start, _end, _array in self.array_ranges]
        self.blob_ranges = sorted(
            (int(blob["va"], 16), int(blob["va"], 16) + int(blob["size"], 16), blob)
            for blob in self.blobs
        )
        self.blob_starts = [start for start, _end, _blob in self.blob_ranges]

    def function_by_name(self, name: str) -> dict[str, Any] | None:
        if name in self.analyzer.user_by_name:
            return self.analyzer.user_by_name[name]
        for function in self.analyzer.user_functions:
            if function.get("FullName") == name:
                return function
        return None

    def value_for_address(self, address: int) -> Value | None:
        array_match = range_item_for_address(self.array_ranges, self.array_starts, address)
        if array_match is not None:
            start, _end, array = array_match
            return Value(
                "constant_array",
                array["id"],
                start,
                metadata={
                    "offset": hex(address - start),
                    "section": array["section"],
                    "size": array["size"],
                    "entropy": array["entropy"],
                },
            )
        blob_match = range_item_for_address(self.blob_ranges, self.blob_starts, address)
        if blob_match is not None:
            start, _end, blob = blob_match
            return Value(
                "data_blob",
                blob["id"],
                start,
                metadata={
                    "offset": hex(address - start),
                    "section": blob["section"],
                    "size": blob["size"],
                },
            )
        if address in self.analyzer.string_data:
            value = self.analyzer.string_data[address]
            return Value("global_string", value, address, value=value)
        if address in self.analyzer.string_headers:
            value = self.analyzer.string_headers[address]
            return Value("global_string_header", value, address, value=value)
        if address in self.analyzer.user_by_start:
            function = self.analyzer.user_by_start[address]["FullName"]
            return Value("function", function, address)
        return None

    def read_string_at(self, address: int, length: int) -> str | None:
        return self.analyzer.read_string_at(address, length)


def range_item_for_address(
    ranges: list[tuple[int, int, dict[str, Any]]], starts: list[int], address: int
) -> tuple[int, int, dict[str, Any]] | None:
    index = bisect_right(starts, address) - 1
    if index < 0:
        return None
    start, end, item = ranges[index]
    if start <= address < end:
        return start, end, item
    return None


class FunctionDataflow:
    def __init__(self, context: DataflowContext, name: str, function: dict[str, Any]):
        self.context = context
        self.name = name
        self.function = function
        self.registers: dict[str, Value] = {}
        self.stack_slots: dict[tuple[str, int], Value] = {}
        self.pushed_args: list[Value] = []
        self.facts = {
            "call_arguments": [],
            "value_flows": [],
            "struct_field_accesses": [],
            "string_field_candidates": [],
            "slice_arg_candidates": [],
        }

    def analyze(self) -> dict[str, Any]:
        for insn in self.context.analyzer.function_content(self.function):
            mnemonic = insn.mnemonic.lower()
            if mnemonic == "call":
                self._record_call(insn)
                self._clobber_call_registers(insn)
                self._clear_call_stack_args()
                continue
            if mnemonic == "push" and insn.operands:
                self._record_push_arg(insn)
                continue
            self._record_struct_field_load(insn)
            self._update_memory_store(insn)
            self._update_register(insn)
        return self.facts

    def _record_call(self, insn) -> None:
        target = self._call_target(insn)
        if is_runtime_noise_call(target):
            return
        args = []
        for reg in call_arg_registers(self.context.analyzer.binary_view.arch):
            value = self.registers.get(reg)
            if value is not None:
                args.append({"reg": reg, **value.to_dict()})

        string_args = self._string_args()
        slice_args = self._slice_args()
        stack_args = self._stack_args()
        string_args.extend(self._stack_string_args(stack_args))
        slice_args.extend(self._stack_slice_args(stack_args))
        if args or stack_args or string_args or slice_args:
            self.facts["call_arguments"].append(
                {
                    "address": hex(insn.address),
                    "target": target,
                    "args": args,
                    "stack_args": stack_args,
                    "string_args": string_args,
                    "slice_args": slice_args,
                }
            )

        flow_args = list(args)
        flow_args.extend({"reg": arg["slot"], **arg["value"]} for arg in stack_args)
        for arg in flow_args:
            if arg["kind"] in {"constant_array", "data_blob", "global_string"}:
                self.facts["value_flows"].append(
                    {
                        "from": arg["label"],
                        "from_kind": arg["kind"],
                        "to": target,
                        "to_kind": "call_argument",
                        "reg": arg["reg"],
                        "address": hex(insn.address),
                    }
                )
        self.facts["slice_arg_candidates"].extend(slice_args)

    def _call_target(self, insn) -> str:
        if insn.operands and insn.operands[0].type == X86_OP_IMM:
            return self.context.analyzer.resolve_direct_call(int(insn.operands[0].imm))[0]
        return "indirect_call"

    def _string_args(self) -> list[dict[str, Any]]:
        if self.context.analyzer.binary_view.arch == "x86":
            return []
        results = []
        for ptr_reg, len_reg in STRING_ARG_REG_PAIRS:
            pointer = self.registers.get(ptr_reg)
            length = self.registers.get(len_reg)
            if pointer is None or length is None or length.kind != "int":
                continue
            if pointer.address is None:
                continue
            text = self.context.read_string_at(pointer.address, int(length.value))
            if text is None:
                continue
            results.append(
                {
                    "ptr_reg": ptr_reg,
                    "len_reg": len_reg,
                    "value": text,
                    "source": pointer.to_dict(),
                    "length": length.value,
                }
            )
        return results

    def _slice_args(self) -> list[dict[str, Any]]:
        if self.context.analyzer.binary_view.arch == "x86":
            return []
        results = []
        for ptr_reg, len_reg, cap_reg in SLICE_ARG_REG_TRIPLES:
            pointer = self.registers.get(ptr_reg)
            length = self.registers.get(len_reg)
            cap = self.registers.get(cap_reg)
            if pointer is None or length is None or cap is None:
                continue
            if length.kind != "int" or cap.kind != "int":
                continue
            if pointer.kind not in {"constant_array", "data_blob", "ptr", "stack_address"}:
                continue
            results.append(
                {
                    "ptr_reg": ptr_reg,
                    "len_reg": len_reg,
                    "cap_reg": cap_reg,
                    "source": pointer.to_dict(),
                    "length": length.value,
                    "cap": cap.value,
                }
            )
        return results

    def _stack_args(self) -> list[dict[str, Any]]:
        if self.context.analyzer.binary_view.arch != "x86":
            return []
        values = stack_args_from_state(
            self.stack_slots,
            self.pushed_args,
            self.context.analyzer.binary_view.pointer_size,
        )
        return [
            {"slot": f"stack[{index}]", "value": value.to_dict()}
            for index, value in enumerate(values)
            if value is not None
        ]

    def _stack_string_args(self, stack_args: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_index = stack_args_by_index(stack_args)
        results = []
        for index in range(0, max(by_index, default=-1), 2):
            pointer = by_index.get(index)
            length = by_index.get(index + 1)
            if pointer is None or length is None or length.kind != "int":
                continue
            if pointer.address is None:
                continue
            text = self.context.read_string_at(pointer.address, int(length.value))
            if text is None:
                continue
            results.append(
                {
                    "ptr_reg": f"stack[{index}]",
                    "len_reg": f"stack[{index + 1}]",
                    "value": text,
                    "source": pointer.to_dict(),
                    "length": length.value,
                }
            )
        return results

    def _stack_slice_args(self, stack_args: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_index = stack_args_by_index(stack_args)
        results = []
        for index in range(0, max(by_index, default=-1) - 1, 3):
            pointer = by_index.get(index)
            length = by_index.get(index + 1)
            cap = by_index.get(index + 2)
            if pointer is None or length is None or cap is None:
                continue
            if length.kind != "int" or cap.kind != "int":
                continue
            if pointer.kind not in {"constant_array", "data_blob", "ptr", "stack_address"}:
                continue
            results.append(
                {
                    "ptr_reg": f"stack[{index}]",
                    "len_reg": f"stack[{index + 1}]",
                    "cap_reg": f"stack[{index + 2}]",
                    "source": pointer.to_dict(),
                    "length": length.value,
                    "cap": cap.value,
                }
            )
        return results

    def _record_struct_field_load(self, insn) -> None:
        if insn.mnemonic.lower() not in MOV_LIKE or len(insn.operands) < 2:
            return
        dest, src = insn.operands[0], insn.operands[1]
        if dest.type != X86_OP_REG or src.type != X86_OP_MEM:
            return
        base = canonical_register(src.mem.base)
        if base is None or base in {"RSP", "RBP", "RIP"}:
            return
        base_value = self.registers.get(base)
        field = {
            "instruction": hex(insn.address),
            "dest_reg": canonical_register(dest.reg),
            "base_reg": base,
            "field_offset": hex(src.mem.disp),
            "base_value": base_value.to_dict() if base_value else None,
        }
        self.facts["struct_field_accesses"].append(field)

    def _update_memory_store(self, insn) -> None:
        if insn.mnemonic.lower() not in {"mov", "movabs"} or len(insn.operands) < 2:
            return
        dest, src = insn.operands[0], insn.operands[1]
        if dest.type != X86_OP_MEM:
            return
        slot = stack_slot(dest)
        if slot is None:
            return
        value = self._value_from_operand(insn, src)
        if value is None:
            self.stack_slots.pop(slot.key(), None)
            return
        self.stack_slots[slot.key()] = value

    def _update_register(self, insn) -> None:
        if not insn.operands or insn.operands[0].type != X86_OP_REG:
            return
        dest_reg = canonical_register(insn.operands[0].reg)
        if dest_reg is None:
            return
        if insn.mnemonic.lower() in MOV_LIKE and len(insn.operands) >= 2:
            value = self._value_from_operand(insn, insn.operands[1])
            if value is not None:
                self.registers[dest_reg] = value
                self._record_string_field_candidate(dest_reg, value, insn.address)
                return
        if insn.mnemonic.lower() in {"xor", "sub"} and len(insn.operands) == 2:
            left, right = insn.operands
            if left.type == X86_OP_REG and right.type == X86_OP_REG and left.reg == right.reg:
                self.registers[dest_reg] = Value("int", "0", value=0)
                return
        self.registers.pop(dest_reg, None)

    def _record_string_field_candidate(self, dest_reg: str, value: Value, address: int) -> None:
        if value.kind not in {"field_load", "int"}:
            return
        for ptr_reg, len_reg in STRING_ARG_REG_PAIRS:
            pointer = self.registers.get(ptr_reg)
            length = self.registers.get(len_reg)
            if pointer is None or length is None:
                continue
            if pointer.kind != "field_load" or length.kind != "field_load":
                continue
            if pointer.metadata.get("base_reg") != length.metadata.get("base_reg"):
                continue
            ptr_offset = int(pointer.metadata.get("field_offset", "0"), 16)
            len_offset = int(length.metadata.get("field_offset", "0"), 16)
            if len_offset != ptr_offset + 8:
                continue
            candidate = {
                "instruction": hex(address),
                "base_reg": pointer.metadata["base_reg"],
                "pointer_offset": hex(ptr_offset),
                "length_offset": hex(len_offset),
                "ptr_reg": ptr_reg,
                "len_reg": len_reg,
            }
            if candidate not in self.facts["string_field_candidates"]:
                self.facts["string_field_candidates"].append(candidate)

    def _value_from_operand(self, insn, operand) -> Value | None:
        if operand.type == X86_OP_REG:
            reg = canonical_register(operand.reg)
            return self.registers.get(reg) if reg else None
        if operand.type == X86_OP_IMM:
            address_value = self.context.value_for_address(int(operand.imm))
            if address_value is not None:
                return address_value
            return Value("int", hex(int(operand.imm)), value=int(operand.imm))
        if operand.type == X86_OP_MEM:
            target = memory_target(insn, operand, self.context.analyzer.binary_view.arch)
            if target is not None:
                address_value = self.context.value_for_address(target)
                if address_value is not None and insn.mnemonic.lower() == "lea":
                    return address_value
                if address_value is not None:
                    return address_value
                if insn.mnemonic.lower() == "lea":
                    return Value("ptr", hex(target), address=target)
            slot = stack_slot(operand)
            if slot is not None and slot.key() in self.stack_slots:
                return self.stack_slots[slot.key()]
            base = canonical_register(operand.mem.base)
            if base is not None and base not in {"RSP", "RBP", "RIP"}:
                base_value = self.registers.get(base)
                return Value(
                    "field_load",
                    f"{base}+{operand.mem.disp:#x}",
                    metadata={
                        "base_reg": base,
                        "field_offset": hex(operand.mem.disp),
                        "base_value": base_value.to_dict() if base_value else None,
                    },
                )
            if insn.mnemonic.lower() == "lea" and slot is not None:
                return Value("stack_address", f"{slot.base}{slot.disp:+#x}", metadata=slot.to_dict())
        return None

    def _record_push_arg(self, insn) -> None:
        if self.context.analyzer.binary_view.arch != "x86":
            return
        value = self._value_from_operand(insn, insn.operands[0])
        if value is None:
            return
        self.pushed_args.insert(0, value)
        del self.pushed_args[16:]

    def _clobber_call_registers(self, insn) -> None:
        target = self._call_target(insn)
        if is_runtime_noise_call(target):
            for reg in call_arg_registers(self.context.analyzer.binary_view.arch):
                self.registers.pop(reg, None)
            return
        self.registers["RAX"] = Value(
            "call_return",
            target,
            metadata={"call_address": hex(insn.address), "target": target},
        )
        for reg in call_arg_registers(self.context.analyzer.binary_view.arch):
            if reg != "RAX":
                self.registers.pop(reg, None)

    def _clear_call_stack_args(self) -> None:
        self.pushed_args.clear()
        self.stack_slots = {
            key: value
            for key, value in self.stack_slots.items()
            if key[0] != "RSP" or key[1] < 0
        }


def has_interesting_facts(facts: dict[str, Any]) -> bool:
    return any(facts.get(key) for key in facts)


def summarize_dataflow(functions: dict[str, Any]) -> dict[str, int]:
    summary = {
        "function_count": len(functions),
        "call_argument_count": 0,
        "value_flow_count": 0,
        "struct_field_access_count": 0,
        "string_field_candidate_count": 0,
        "slice_arg_candidate_count": 0,
    }
    for facts in functions.values():
        summary["call_argument_count"] += len(facts.get("call_arguments", []))
        summary["value_flow_count"] += len(facts.get("value_flows", []))
        summary["struct_field_access_count"] += len(facts.get("struct_field_accesses", []))
        summary["string_field_candidate_count"] += len(facts.get("string_field_candidates", []))
        summary["slice_arg_candidate_count"] += len(facts.get("slice_arg_candidates", []))
    return summary


def stack_slot(operand) -> MemorySlot | None:
    if operand.type != X86_OP_MEM:
        return None
    base = canonical_register(operand.mem.base)
    if base not in {"RSP", "RBP"}:
        return None
    return MemorySlot(base, operand.mem.disp)


def rip_target(insn, operand) -> int:
    return x86_rip_target(insn, operand)


def canonical_register(reg_id: int) -> str | None:
    return canonical_x86_register(reg_id)


def call_arg_registers(arch: str) -> tuple[str, ...]:
    if arch == "x86":
        return ()
    return ABI_INT_REGS


def stack_args_from_state(
    stack_slots: dict[tuple[str, int], Value],
    pushed_args: list[Value],
    pointer_size: int,
) -> list[Value | None]:
    slot_indexes = [
        disp // pointer_size
        for base, disp in stack_slots
        if base == "RSP" and 0 <= disp <= 0x100 and disp % pointer_size == 0
    ]
    max_index = max([len(pushed_args) - 1] + slot_indexes, default=-1)
    if max_index < 0:
        return []
    values: list[Value | None] = [None] * (max_index + 1)
    for index, value in enumerate(pushed_args):
        values[index] = value
    for (base, disp), value in stack_slots.items():
        if base != "RSP" or disp < 0 or disp > 0x100 or disp % pointer_size != 0:
            continue
        values[disp // pointer_size] = value
    return values


def stack_args_by_index(stack_args: list[dict[str, Any]]) -> dict[int, Value]:
    result = {}
    for arg in stack_args:
        slot = arg.get("slot", "")
        if not slot.startswith("stack[") or not slot.endswith("]"):
            continue
        try:
            index = int(slot[6:-1])
        except ValueError:
            continue
        value = arg.get("value") or {}
        result[index] = Value(
            kind=value.get("kind", "unknown"),
            label=value.get("label", ""),
            address=int(value["address"], 16) if value.get("address") else None,
            value=value.get("value"),
            metadata=value.get("metadata") or {},
        )
    return result
