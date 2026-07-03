import argparse
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import *

from semantic_analysis import analyze_semantics

DEFAULT_BINARY = Path(
    "data/8851adcfe1aea93461dec645a4d15180ae75fd7719797be0cc443e0f59fb164a.exe"
)
ABI_INT_REGS = ("RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11")
STRING_ARG_REG_PAIRS = (("RAX", "RBX"), ("RCX", "RDI"), ("RSI", "R8"), ("R9", "R10"))
MOV_LIKE = {"mov", "movabs", "lea"}
CALLBACK_CONSUMERS = {"path/filepath.Walk", "path/filepath.WalkDir"}
MAX_STRING_ARG_LEN = 4096


REG_ALIASES = {
    X86_REG_RAX: "RAX",
    X86_REG_EAX: "RAX",
    X86_REG_AX: "RAX",
    X86_REG_AL: "RAX",
    X86_REG_AH: "RAX",
    X86_REG_RBX: "RBX",
    X86_REG_EBX: "RBX",
    X86_REG_BX: "RBX",
    X86_REG_BL: "RBX",
    X86_REG_BH: "RBX",
    X86_REG_RCX: "RCX",
    X86_REG_ECX: "RCX",
    X86_REG_CX: "RCX",
    X86_REG_CL: "RCX",
    X86_REG_CH: "RCX",
    X86_REG_RDI: "RDI",
    X86_REG_EDI: "RDI",
    X86_REG_DI: "RDI",
    X86_REG_DIL: "RDI",
    X86_REG_RSI: "RSI",
    X86_REG_ESI: "RSI",
    X86_REG_SI: "RSI",
    X86_REG_SIL: "RSI",
    X86_REG_R8: "R8",
    X86_REG_R8D: "R8",
    X86_REG_R8W: "R8",
    X86_REG_R8B: "R8",
    X86_REG_R9: "R9",
    X86_REG_R9D: "R9",
    X86_REG_R9W: "R9",
    X86_REG_R9B: "R9",
    X86_REG_R10: "R10",
    X86_REG_R10D: "R10",
    X86_REG_R10W: "R10",
    X86_REG_R10B: "R10",
    X86_REG_R11: "R11",
    X86_REG_R11D: "R11",
    X86_REG_R11W: "R11",
    X86_REG_R11B: "R11",
    # These are not ABI integer argument registers, but tracking them lets us
    # follow short register-to-register moves before an argument register is set.
    X86_REG_RDX: "RDX",
    X86_REG_EDX: "RDX",
    X86_REG_DX: "RDX",
    X86_REG_DL: "RDX",
    X86_REG_DH: "RDX",
    X86_REG_RBP: "RBP",
    X86_REG_EBP: "RBP",
    X86_REG_BP: "RBP",
    X86_REG_BPL: "RBP",
}


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
    def __init__(self, binary_path: Path, goresym_path: Path):
        self.binary_path = binary_path
        self.goresym_path = goresym_path
        self.binary = lief.parse(str(binary_path))
        if self.binary is None:
            raise RuntimeError(f"Could not parse binary: {binary_path}")

        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
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
        self.calls_by_function: dict[str, list[Call]] = {}

    def _run_goresym(self) -> dict[str, Any]:
        command = [
            str(self.goresym_path.resolve()),
            "-strings",
            "-d",
            str(self.binary_path),
        ]
        proc = subprocess.run(command, text=True, capture_output=True, check=False)
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
        size = function["End"] - function["Start"]
        code = bytes(self.binary.get_content_from_virtual_address(start, size))
        return list(self.disassembler.disasm(code, start))

    def resolve_direct_call(self, target: int) -> tuple[str, str]:
        if target in self.user_by_start:
            return self.user_by_start[target]["FullName"], "user"
        if target in self.std_by_start:
            return self.std_by_start[target]["FullName"], "std"
        containing_user = function_containing(self.user_ranges, target)
        if containing_user is not None:
            offset = target - containing_user["Start"]
            return f"{containing_user['FullName']}+0x{offset:x}", "user"
        containing_std = function_containing(self.std_ranges, target)
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

        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            target = rip_target(insn, operand)
            value = self.value_from_address(target)
            if value is not None:
                return value
            if insn.mnemonic == "lea":
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

        for start, end, value in self.string_ranges:
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

        if target_name.startswith("runtime."):
            return Call(
                insn.address,
                target_name,
                op.imm,
                kind,
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

        return Call(insn.address, target_name, op.imm, kind, string_args, arg_registers)

    def analyze_function(self, function: dict[str, Any]) -> list[Call]:
        name = function["FullName"]
        if name in self.calls_by_function:
            return self.calls_by_function[name]

        registers: dict[str, RegisterValue] = {}
        last_function_literal: RegisterValue | None = None
        calls = []
        for insn in self.function_content(function):
            call = self.call_from_instruction(insn, registers, last_function_literal)
            if insn.mnemonic == "call":
                if call is not None:
                    calls.append(call)
                    if call.via is not None:
                        last_function_literal = None
                else:
                    last_function_literal = None
                for reg in ABI_INT_REGS:
                    registers.pop(reg, None)
                continue
            value = self.update_registers(insn, registers)
            if value is not None and value.kind == "function":
                last_function_literal = value

        self.calls_by_function[name] = calls
        return calls
    def find_function_end(self, start: int) -> int:
        MAX_SCAN = 0x10000

        code = bytes(
            self.binary.get_content_from_virtual_address(start, MAX_SCAN)
        )

        offset = code.find(b"\xCC")  # INT3

        if offset == -1:
            raise RuntimeError(f"Couldn't find function end for {hex(start)}")

        return start + offset

    def synthetic_function(self, call: Call)->dict[str, Any]:
        if call.target_address is None:
            raise ValueError("Call has no target address")
        return {
            "Start": call.target_address,
            "End": self.find_function_end(call.target_address),
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
                    visit(self.synthetic_function(call))
        visit(entry)
        return graph


def canonical_reg(reg_id: int) -> str | None:
    return REG_ALIASES.get(reg_id)


def rip_target(insn, operand) -> int:
    return insn.address + insn.size + operand.mem.disp


def function_containing(functions: list[dict[str, Any]], address: int) -> dict[str, Any] | None:
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

    blobs = semantics.get("suspicious_data_blobs") or []
    if blobs:
        lines.append("  suspicious_data_blobs:")
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


if __name__ == "__main__":
    #args = parse_args()
    data = Path("data").glob("*.exe")
    output = Path("output")
    output.mkdir(parents=True, exist_ok=True)
    for binary in data:
        try:
            graph, semantics, seri = main(binary, Path("GoReSym"), "main.main")
            binName = binary.name.split('.', 1)[0]
            with open(str(output/binName)+".json", "w") as f:
                json.dump(seri, f, indent=2)
            with open(str(output/binName)+".txt", "w") as f:
                f.write(format_human_readable_report(graph, semantics))

        except:
            pass
