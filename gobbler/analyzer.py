import argparse
from bisect import bisect_right
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief
from capstone import CS_ARCH_X86, Cs
from capstone.x86 import *

from gobbler.arch import capstone_mode, canonical_register, memory_target
from gobbler.binary import BinaryView
from gobbler.output.formatters import format_human_readable_report as format_report
from gobbler.utils.noise import is_runtime_noise_call
from gobbler.passes.semantic import analyze_semantics

DEFAULT_BINARY = Path(
    "data/8851adcfe1aea93461dec645a4d15180ae75fd7719797be0cc443e0f59fb164a.exe"
)
ABI_INT_REGS = ("RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11")
STRING_ARG_REG_PAIRS = (("RAX", "RBX"), ("RCX", "RDI"), ("RSI", "R8"), ("R9", "R10"))
MOV_LIKE = {"mov", "movabs", "lea"}
CALLBACK_CONSUMERS = {"path/filepath.Walk", "path/filepath.WalkDir"}
MAX_STRING_ARG_LEN = 4096
DEFAULT_GORESYM_TIMEOUT = 120.0


@dataclass(frozen=True)
class RegisterValue:
    kind: str
    value: Any
    address: int | None = None


@dataclass
class Call:
    address: int
    target: str
    target_address: int | None
    kind: str
    string_args: list[str] = field(default_factory=list)
    arg_registers: dict[str, str] = field(default_factory=dict)
    via: str | None = None
    visible: bool = True

    def display(self) -> str:
        target = self.target
        if not self.string_args:
            return f"{self.via} -> {target}" if self.via else target
        args = ", ".join(json.dumps(arg) for arg in self.string_args)
        target_with_args = f"{target}({args})"
        return f"{self.via} -> {target_with_args}" if self.via else target_with_args


class Analyzer:
    def __init__(
        self,
        binary_path: Path,
        goresym_path: Path,
        goresym_timeout: float | None = DEFAULT_GORESYM_TIMEOUT,
    ):
        self.binary_path = binary_path
        self.goresym_path = goresym_path
        self.goresym_timeout = goresym_timeout
        self.binary = lief.parse(str(binary_path))
        if self.binary is None:
            raise RuntimeError(f"Could not parse binary: {binary_path}")
        self.binary_view = BinaryView(self.binary)
        self.binary_view.ensure_supported()

        self.disassembler = Cs(CS_ARCH_X86, capstone_mode(self.binary_view.arch))
        self.disassembler.detail = True

        self.goresym = self._run_goresym()
        self.user_functions = self.goresym.get("UserFunctions") or []
        self.std_functions = self.goresym.get("StdFunctions") or []
        self.user_by_start = {f["Start"]: f for f in self.user_functions}
        self.std_by_start = {f["Start"]: f for f in self.std_functions}
        self.user_ranges = sorted(
            self.user_functions, key=lambda function: function["Start"]
        )
        self.std_ranges = sorted(
            self.std_functions, key=lambda function: function["Start"]
        )
        self.user_range_starts = [function["Start"] for function in self.user_ranges]
        self.std_range_starts = [function["Start"] for function in self.std_ranges]
        self.user_by_name = {f["FullName"]: f for f in self.user_functions}
        self.user_by_short_name = {
            f["FullName"].split("/")[-1]: f for f in self.user_functions
        }
        strings = self.goresym.get("Strings") or []
        self.string_headers = {
            s["HeaderAddress"]: s["String"] for s in strings if "HeaderAddress" in s
        }
        self.string_data = {
            s["DataAddress"]: s["String"] for s in strings if "DataAddress" in s
        }
        self.all_string_addresses = self.string_headers | self.string_data
        self.string_ranges = [
            (address, address + len(value.encode("utf-8", errors="replace")), value)
            for address, value in self.string_data.items()
        ]
        self.string_ranges.sort(key=lambda item: item[0])
        self.string_range_starts = [item[0] for item in self.string_ranges]
        self.calls_by_function: dict[str, list[Call]] = {}
        self.instructions_by_function: dict[tuple[int, int], list[Any]] = {}

    def _run_goresym(self) -> dict[str, Any]:
        command = [
            str(self.goresym_path.resolve()),
            "-strings",
            "-d",
            str(self.binary_path),
        ]
        try:
            proc = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.goresym_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"GoReSym timed out after {self.goresym_timeout}s"
            ) from exc
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "GoReSym failed")
        return json.loads(proc.stdout)

    def function_by_entry_name(self, name: str) -> dict[str, Any]:
        if name in self.user_by_name:
            return self.user_by_name[name]
        if name in self.user_by_short_name:
            return self.user_by_short_name[name]
        raise KeyError(f"User function not found: {name}")

    def function_content(self, function: dict[str, Any]):
        start = function["Start"]
        end = function["End"]
        key = (start, end)
        cached = self.instructions_by_function.get(key)
        if cached is not None:
            return cached
        size = end - start
        code = bytes(self.binary.get_content_from_virtual_address(start, size))
        instructions = list(self.disassembler.disasm(code, start))
        self.instructions_by_function[key] = instructions
        return instructions

    def resolve_direct_call(self, target: int) -> tuple[str, str]:
        if target in self.user_by_start:
            return self.user_by_start[target]["FullName"], "user"
        if target in self.std_by_start:
            return self.std_by_start[target]["FullName"], "std"
        containing_user = function_containing(self.user_ranges, target, self.user_range_starts)
        if containing_user is not None:
            offset = target - containing_user["Start"]
            return f"{containing_user['FullName']}+0x{offset:x}", "user"
        containing_std = function_containing(self.std_ranges, target, self.std_range_starts)
        if containing_std is not None:
            offset = target - containing_std["Start"]
            return f"{containing_std['FullName']}+0x{offset:x}", "std"
        return f"unknown_{target:x}", "unknown"

    def value_from_operand(
        self, insn, operand, registers: dict[str, RegisterValue]
    ) -> RegisterValue | None:
        if operand.type == X86_OP_REG:
            reg = canonical_reg(operand.reg)
            if reg:
                return registers.get(reg)
            return None

        if operand.type == X86_OP_IMM:
            value = self.value_from_address(operand.imm)
            if value is not None:
                return value
            return RegisterValue("int", operand.imm)

        if operand.type == X86_OP_MEM:
            target = memory_target(insn, operand, self.binary_view.arch)
            if target is None:
                return None
            value = self.value_from_address(target)
            if value is not None:
                return value
            if insn.mnemonic.lower() == "lea":
                return RegisterValue("ptr", target, target)

        return None

    def value_from_address(self, address: int) -> RegisterValue | None:
        if address in self.user_by_start:
            return RegisterValue(
                "function", self.user_by_start[address]["FullName"], address
            )
        if address in self.string_data:
            return RegisterValue("string", self.string_data[address], address)
        if address in self.string_headers:
            return RegisterValue("string", self.string_headers[address], address)
        return None

    def read_string_at(self, address: int, length: int) -> str | None:
        if length <= 0 or length > MAX_STRING_ARG_LEN:
            return None

        index = bisect_right(self.string_range_starts, address) - 1
        if index >= 0:
            start, end, value = self.string_ranges[index]
            if start <= address and address + length <= end:
                offset = address - start
                data = value.encode("utf-8", errors="replace")[offset : offset + length]
                return decode_printable(data)

        try:
            data = bytes(self.binary.get_content_from_virtual_address(address, length))
        except Exception:
            return None
        return decode_printable(data)

    def string_from_pair(
        self, pointer: RegisterValue | None, length: RegisterValue | None
    ) -> str | None:
        if pointer is None or length is None or length.kind != "int":
            return None
        if pointer.kind not in {"ptr", "string"} or pointer.address is None:
            return None

        text = self.read_string_at(pointer.address, length.value)
        if text is not None:
            return text

        if pointer.kind == "string":
            encoded = pointer.value.encode("utf-8", errors="replace")
            if 0 < length.value <= len(encoded):
                return decode_printable(encoded[: length.value])
        return None

    def string_args_from_registers(
        self, registers: dict[str, RegisterValue]
    ) -> tuple[list[str], dict[str, str]]:
        if self.binary_view.arch == "x86":
            return [], {}
        string_args = []
        arg_registers = {}
        seen_strings = set()

        for pointer_reg, length_reg in STRING_ARG_REG_PAIRS:
            text = self.string_from_pair(
                registers.get(pointer_reg), registers.get(length_reg)
            )
            if text is None:
                continue
            if text not in seen_strings:
                string_args.append(text)
                seen_strings.add(text)
            arg_registers[f"{pointer_reg}/{length_reg}"] = text

        for reg in ABI_INT_REGS:
            value = registers.get(reg)
            if value is None or value.kind != "string":
                continue
            if value.value not in seen_strings:
                string_args.append(value.value)
                seen_strings.add(value.value)
            arg_registers[reg] = value.value

        return string_args, arg_registers

    def string_args_from_stack(
        self,
        stack_args: list[RegisterValue | None],
    ) -> tuple[list[str], dict[str, str]]:
        if self.binary_view.arch != "x86":
            return [], {}

        string_args = []
        arg_registers = {}
        seen_strings = set()
        for index in range(0, len(stack_args) - 1, 2):
            pointer = stack_args[index]
            length = stack_args[index + 1]
            text = self.string_from_pair(pointer, length)
            if text is None:
                continue
            if text not in seen_strings:
                string_args.append(text)
                seen_strings.add(text)
            arg_registers[f"stack[{index}]/stack[{index + 1}]"] = text
        return string_args, arg_registers

    def update_registers(
        self, insn, registers: dict[str, RegisterValue]
    ) -> RegisterValue | None:
        if not insn.operands:
            return None

        dest = insn.operands[0]
        if dest.type != X86_OP_REG:
            return None

        dest_reg = canonical_reg(dest.reg)
        if not dest_reg:
            return None

        if insn.mnemonic in MOV_LIKE and len(insn.operands) >= 2:
            value = self.value_from_operand(insn, insn.operands[1], registers)
            if value is not None:
                registers[dest_reg] = value
                return value

        # Any other write means the old tracked value is stale.
        registers.pop(dest_reg, None)
        return None

    def update_stack_arg_slots(
        self,
        insn,
        registers: dict[str, RegisterValue],
        stack_arg_slots: dict[int, RegisterValue],
    ) -> None:
        if self.binary_view.arch != "x86":
            return
        if insn.mnemonic not in {"mov", "movabs"} or len(insn.operands) < 2:
            return
        dest, src = insn.operands[0], insn.operands[1]
        offset = stack_arg_offset(dest)
        if offset is None:
            return
        value = self.value_from_operand(insn, src, registers)
        if value is None:
            stack_arg_slots.pop(offset, None)
            return
        stack_arg_slots[offset] = value

    def call_from_instruction(
        self,
        insn,
        registers: dict[str, RegisterValue],
        last_function_literal: RegisterValue | None,
    ) -> Call | None:
        if insn.mnemonic != "call" or not insn.operands:
            return None

        op = insn.operands[0]
        if op.type != X86_OP_IMM:
            if (
                last_function_literal is not None
                and last_function_literal.kind == "function"
            ):
                return Call(
                    insn.address,
                    last_function_literal.value,
                    last_function_literal.address,
                    "user",
                    via="indirect_call",
                )
            return Call(insn.address, "indirect_call", None, "indirect")

        target_name, kind = self.resolve_direct_call(op.imm)
        if is_runtime_noise_call(target_name):
            return Call(insn.address, target_name, op.imm, kind, visible=False)

        if (
            last_function_literal is not None
            and last_function_literal.kind == "function"
            and target_name.startswith("runtime.newproc")
        ):
            return Call(
                insn.address,
                last_function_literal.value,
                last_function_literal.address,
                "user",
                via=target_name,
                visible=False,
            )


        if (
            last_function_literal is not None
            and last_function_literal.kind == "function"
            and target_name in CALLBACK_CONSUMERS
        ):
            return Call(
                insn.address,
                last_function_literal.value,
                last_function_literal.address,
                "user",
                via=target_name,
            )

        string_args, arg_registers = self.string_args_from_registers(registers)
        stack_string_args, stack_arg_registers = self.string_args_from_stack(
            current_stack_args(registers)
        )
        for arg in stack_string_args:
            if arg not in string_args:
                string_args.append(arg)
        arg_registers.update(stack_arg_registers)

        return Call(insn.address, target_name, op.imm, kind, string_args, arg_registers)

    def analyze_function(self, function: dict[str, Any]) -> list[Call]:
        name = function["FullName"]
        if name in self.calls_by_function:
            return self.calls_by_function[name]

        registers: dict[str, RegisterValue] = {}
        stack_arg_slots: dict[int, RegisterValue] = {}
        pushed_args: list[RegisterValue] = []
        last_function_literal: RegisterValue | None = None
        calls = []
        for insn in self.function_content(function):
            registers["__stack_args__"] = RegisterValue(
                "stack_args",
                stack_args_from_state(stack_arg_slots, pushed_args, self.binary_view.pointer_size),
            )
            call = self.call_from_instruction(insn, registers, last_function_literal)
            if insn.mnemonic == "call":
                if call is not None:
                    calls.append(call)
                else:
                    last_function_literal = None
                last_function_literal = None
                for reg in ABI_INT_REGS:
                    registers.pop(reg, None)
                stack_arg_slots.clear()
                pushed_args.clear()
                continue
            if insn.mnemonic == "push" and insn.operands:
                value = self.value_from_operand(insn, insn.operands[0], registers)
                if value is not None:
                    pushed_args.insert(0, value)
                    del pushed_args[16:]
                continue
            self.update_stack_arg_slots(insn, registers, stack_arg_slots)
            value = self.update_registers(insn, registers)
            if value is not None and value.kind == "function":
                last_function_literal = value

        self.calls_by_function[name] = calls
        return calls
    def find_function_end(self, start: int) -> int | None:
        MAX_SCAN = 0x10000

        try:
            code = bytes(
                self.binary.get_content_from_virtual_address(start, MAX_SCAN)
            )
        except Exception:
            return None

        offset = code.find(b"\xCC")  # INT3

        if offset == -1:
            return None

        return start + offset

    def synthetic_function(self, call: Call) -> dict[str, Any] | None:
        if call.target_address is None:
            return None
        end = self.find_function_end(call.target_address)
        if end is None or end <= call.target_address:
            return None
        return {
            "Start": call.target_address,
            "End": end,
            "FullName": call.target,
        }
        
    def build_reachable_graph(self, entry_name: str) -> dict[str, list[Call]]:
        entry = self.function_by_entry_name(entry_name)
        graph: dict[str, list[Call]] = {}
        visited = set()

        def visit(function: dict[str, Any]) -> None:
            name = function["FullName"]
            if name in visited:
                return
            visited.add(name)

            calls = self.analyze_function(function)
            graph[name] = calls
            #for call in calls:
            #    if call.kind == "user" and call.target_address in self.user_by_start:
            #        visit(self.user_by_start[call.target_address])
            #    elif call.kind == "unknown":
            #        visit(self.synthetic_function(call))
            for call in calls:
                if call.target_address is None:
                    continue

                if call.target_address in self.user_by_start:
                    visit(self.user_by_start[call.target_address])
                elif call.kind == "unknown":
                    synthetic = self.synthetic_function(call)
                    if synthetic is not None:
                        visit(synthetic)
        visit(entry)
        return graph


def canonical_reg(reg_id: int) -> str | None:
    return canonical_register(reg_id)


def current_stack_args(registers: dict[str, RegisterValue]) -> list[RegisterValue | None]:
    stack_args = registers.get("__stack_args__")
    if stack_args is None or stack_args.kind != "stack_args":
        return []
    return list(stack_args.value or [])


def stack_args_from_state(
    slots: dict[int, RegisterValue], pushed_args: list[RegisterValue], pointer_size: int
) -> list[RegisterValue | None]:
    max_index = max(
        [len(pushed_args) - 1]
        + [offset // pointer_size for offset in slots if offset >= 0 and offset % pointer_size == 0],
        default=-1,
    )
    if max_index < 0:
        return []
    args: list[RegisterValue | None] = [None] * (max_index + 1)
    for index, value in enumerate(pushed_args):
        args[index] = value
    for offset, value in slots.items():
        if offset < 0 or offset % pointer_size != 0:
            continue
        index = offset // pointer_size
        if index < len(args):
            args[index] = value
    return args


def stack_arg_offset(operand) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    base = canonical_reg(operand.mem.base)
    if base != "RSP":
        return None
    disp = int(operand.mem.disp)
    if disp < 0 or disp > 0x100:
        return None
    return disp


def function_containing(
    functions: list[dict[str, Any]], address: int, starts: list[int] | None = None
) -> dict[str, Any] | None:
    if starts is not None:
        index = bisect_right(starts, address) - 1
        if index < 0:
            return None
        function = functions[index]
        if function["Start"] <= address < function["End"]:
            return function
        return None
    for function in functions:
        if function["Start"] <= address < function["End"]:
            return function
    return None


def decode_printable(data: bytes) -> str | None:
    if not data:
        return None
    if not all(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def call_to_dict(call: Call) -> dict[str, Any]:
    return {
        "address": hex(call.address),
        "target": call.target,
        "target_address": hex(call.target_address) if call.target_address else None,
        "kind": call.kind,
        "string_args": call.string_args,
        "arg_registers": call.arg_registers,
        "via": call.via,
        "display": call.display(),
    }


def format_graph(graph: dict[str, list[Call]]) -> str:
    lines = []
    for function, calls in graph.items():
        visible_calls = [call for call in calls if call.visible]
        lines.append(function)
        if not visible_calls:
            lines.append("  <no direct calls>")
            continue
        for call in visible_calls:
            lines.append(f"  {hex(call.address)} -> {call.display()}")
    return "\n".join(lines)


def print_graph(graph: dict[str, list[Call]]) -> None:
    print(format_graph(graph))


def format_semantics(semantics: dict[str, Any]) -> str:
    lines = ["Semantic analysis"]
    hints = semantics.get("assessment_hints") or []
    if hints:
        lines.append("  assessment_hints:")
        for hint in hints:
            lines.append(f"    - {hint}")

    transfers = semantics.get("mid_function_control_transfers") or []
    if transfers:
        lines.append("  mid_function_control_transfers:")
        for transfer in transfers[:10]:
            lines.append(
                "    - "
                f"{transfer['display']} "
                f"classification={transfer['classification']}"
            )

    indirect_calls = semantics.get("indirect_calls") or []
    if indirect_calls:
        lines.append("  indirect_calls:")
        for indirect_call in indirect_calls[:10]:
            lines.append(
                "    - "
                f"{indirect_call['display']} "
                f"evidence={'; '.join(indirect_call['evidence'])}"
            )

    blobs = semantics.get("notable_data_blobs") or []
    if blobs:
        lines.append("  notable_data_blobs:")
        for blob in blobs[:10]:
            refs = ", ".join(blob["referenced_by"]) or "<none>"
            lines.append(
                "    - "
                f"{blob['id']} {blob['section']}:{blob['va']} size={blob['size']} "
                f"entropy={blob['entropy']} reasons={','.join(blob['reasons'])} refs={refs}"
            )

    transformers = semantics.get("data_transformers") or []
    if transformers:
        lines.append("  data_transformers:")
        for transformer in transformers[:10]:
            lines.append(
                "    - "
                f"{transformer['function']} ops={','.join(transformer['operations'])} "
                f"confidence={transformer['confidence']} sources={','.join(transformer['input_sources']) or '<unknown>'}"
            )

    loaders = semantics.get("loader_behaviors") or []
    if loaders:
        lines.append("  loader_behaviors:")
        for loader in loaders[:10]:
            lines.append(
                "    - "
                f"{loader['function']} kind={loader['kind']} confidence={loader['confidence']} "
                f"evidence={','.join(loader['evidence'])}"
            )
    return "\n".join(lines)


def print_semantics(semantics: dict[str, Any]) -> None:
    print(format_semantics(semantics))


def format_human_readable_report(
    graph: dict[str, list[Call]], semantics: dict[str, Any]
) -> str:
    return f"{format_graph(graph)}\n\n{format_semantics(semantics)}\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a Go user-function call graph and annotate string arguments."
    )
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        default=DEFAULT_BINARY,
        help=f"Binary to analyze. Defaults to {DEFAULT_BINARY}",
    )
    parser.add_argument(
        "--entry",
        default="main.main",
        help="User function to start from. Defaults to main.main",
    )
    parser.add_argument(
        "--goresym",
        type=Path,
        default=Path("./GoReSym"),
        help="Path to the modified GoReSym binary.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    return parser.parse_args()


def main(binary, goresym, entry, ojson=True) -> None:
    analyzer = Analyzer(binary, goresym)
    graph = analyzer.build_reachable_graph(entry)
    add_fallback_entry_graphs(analyzer, graph)
    semantics = analyze_semantics(analyzer, graph)

    if ojson:
        serializable = {
            "call_graph": {
                function: [call_to_dict(call) for call in calls if call.visible]
                for function, calls in graph.items()
            },
            "semantic_analysis": semantics,
        }
        #print(json.dumps(serializable, indent=2))
        return graph, semantics, serializable


def add_fallback_entry_graphs(analyzer: Analyzer, graph: dict[str, list[Call]]) -> None:
    if any(call.visible for calls in graph.values() for call in calls):
        return
    for function in fallback_entry_functions(analyzer):
        try:
            extra = analyzer.build_reachable_graph(function["FullName"])
        except Exception:
            continue
        for name, calls in extra.items():
            graph.setdefault(name, calls)


def fallback_entry_functions(analyzer: Analyzer) -> list[dict[str, Any]]:
    candidates = []
    for function in analyzer.user_functions:
        name = function.get("FullName", "")
        if not name.startswith("main."):
            continue
        short_name = name.rsplit(".", 1)[-1]
        if name == "main.main" or name.startswith(("main._Cfunc_", "main._cgo_")):
            continue
        if short_name.startswith("init") or short_name[:1].isupper():
            candidates.append(function)
    return sorted(candidates, key=lambda item: item["Start"])[:12]


if __name__ == "__main__":
    from gobbler.cli import main as cli_main

    raise SystemExit(cli_main())
