from __future__ import annotations

from typing import Any

from capstone import CS_MODE_32, CS_MODE_64
from capstone.x86 import *


SUPPORTED_ARCHES = {"x86", "x86_64"}


def capstone_mode(arch: str) -> int:
    if arch == "x86":
        return CS_MODE_32
    if arch == "x86_64":
        return CS_MODE_64
    raise RuntimeError(f"Unsupported x86 disassembly architecture: {arch}")


def word_size(arch: str) -> int:
    return 4 if arch == "x86" else 8


def is_x86_32(arch: str) -> bool:
    return arch == "x86"


def canonical_register(reg_id: int) -> str | None:
    aliases = {
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
        X86_REG_RDX: "RDX",
        X86_REG_EDX: "RDX",
        X86_REG_DX: "RDX",
        X86_REG_DL: "RDX",
        X86_REG_DH: "RDX",
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
        X86_REG_RSP: "RSP",
        X86_REG_ESP: "RSP",
        X86_REG_SP: "RSP",
        X86_REG_RBP: "RBP",
        X86_REG_EBP: "RBP",
        X86_REG_BP: "RBP",
        X86_REG_RIP: "RIP",
        X86_REG_EIP: "RIP",
    }
    return aliases.get(reg_id)


def memory_target(insn: Any, operand: Any, arch: str) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    mem = operand.mem
    if mem.base == X86_REG_RIP:
        return rip_target(insn, operand)
    if arch == "x86" and not mem.base and not mem.index and mem.disp:
        return int(mem.disp)
    return None


def memory_target_access(insn: Any, operand: Any, arch: str) -> tuple[int, str] | None:
    target = memory_target(insn, operand, arch)
    if target is None:
        return None
    if operand.mem.base == X86_REG_RIP:
        return target, "rip_relative_memory"
    return target, "absolute_memory"


def rip_target(insn: Any, operand: Any) -> int:
    return int(insn.address) + int(insn.size) + int(operand.mem.disp)
