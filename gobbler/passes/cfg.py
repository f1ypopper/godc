from dataclasses import dataclass
from typing import Any

from capstone.x86 import *


TRANSFORM_MNEMONICS = {"xor", "add", "sub", "rol", "ror", "not"}
READ_MODIFY_WRITE_MNEMONICS = {"xor", "add", "sub", "rol", "ror", "not"}
MAX_CFG_INSTRUCTIONS = 50000
MAX_LOOP_INSTRUCTIONS = 8000


@dataclass(frozen=True, slots=True)
class InstructionFact:
    address: int
    size: int
    mnemonic: str
    branch_target: int | None
    is_conditional_jump: bool
    memory_reads: int
    memory_writes: int
    byte_memory_ops: int
    transform_op: str | None


@dataclass(frozen=True, slots=True)
class BasicBlock:
    id: str
    start: int
    end: int
    start_index: int
    end_index: int


def analyze_cfg(analyzer: Any, graph: dict[str, list[Any]]) -> dict[str, Any]:
    functions = {}
    for function_name in graph:
        function = function_by_name(analyzer, function_name)
        if function is None:
            continue
        facts = analyze_function_cfg(analyzer, function_name, function)
        if facts["loop_count"] or facts["probable_transform_loops"]:
            functions[function_name] = facts
    return {
        "functions": functions,
        "summary": summarize_cfg(functions),
    }


def analyze_function_cfg(analyzer: Any, function_name: str, function: dict[str, Any]) -> dict[str, Any]:
    insns = analyzer.function_content(function)
    if not insns:
        return empty_cfg_summary()
    if len(insns) > MAX_CFG_INSTRUCTIONS:
        return {
            **empty_cfg_summary(),
            "skipped": "too_many_instructions",
            "instruction_count": len(insns),
        }

    facts = [instruction_fact(insn) for insn in insns]
    starts = {facts[0].address}
    has_backward_jump = False
    has_transform_op = False
    function_start = function["Start"]
    function_end = function["End"]
    for index, fact in enumerate(facts):
        if fact.transform_op is not None:
            has_transform_op = True
        target = fact.branch_target
        if target is not None and function_start <= target < function_end:
            starts.add(target)
            if target <= fact.address:
                has_backward_jump = True
            if index + 1 < len(facts):
                starts.add(facts[index + 1].address)

    if not has_backward_jump:
        return empty_cfg_summary()

    sorted_starts = sorted(starts)
    address_to_index = {fact.address: index for index, fact in enumerate(facts)}
    block_for_address = {}
    blocks: list[BasicBlock] = []
    for index, start in enumerate(sorted_starts):
        end = sorted_starts[index + 1] if index + 1 < len(sorted_starts) else function_end
        start_index = address_to_index.get(start)
        if start_index is None:
            continue
        end_index = address_to_index.get(end, len(insns))
        if start_index >= end_index:
            continue
        block_id = f"{function_name}:block_{len(blocks)}"
        block_for_address[start] = block_id
        last = facts[end_index - 1]
        blocks.append(
            BasicBlock(
                id=block_id,
                start=start,
                end=last.address + last.size,
                start_index=start_index,
                end_index=end_index,
            )
        )

    edges = []
    loop_edges = []
    for index, block in enumerate(blocks):
        last = facts[block.end_index - 1]
        target = last.branch_target
        if target is not None and target in block_for_address:
            edge = {
                "from": block.id,
                "to": block_for_address[target],
                "type": "jump",
                "instruction": hex(last.address),
            }
            edges.append(edge)
            if target <= block.start:
                loop_edges.append(edge)
        if last.is_conditional_jump and index + 1 < len(blocks):
            edges.append(
                {
                    "from": block.id,
                    "to": blocks[index + 1].id,
                    "type": "fallthrough",
                    "instruction": hex(last.address),
                }
            )

    transform_loops = []
    prefixes = fact_prefixes(facts) if loop_edges and has_transform_op else None
    for edge in loop_edges:
        loop_start = int(edge["to"].split("_")[-1])
        loop_end = int(edge["from"].split("_")[-1])
        if loop_start > loop_end or loop_end >= len(blocks):
            continue
        start_index = blocks[loop_start].start_index
        end_index = blocks[loop_end].end_index
        loop_instruction_count = end_index - start_index
        if loop_instruction_count > MAX_LOOP_INSTRUCTIONS:
            continue
        if prefixes is None:
            continue
        evidence = loop_transform_evidence_from_prefix(prefixes, start_index, end_index)
        has_strong_transform = bool(
            {"xor", "rol", "ror", "not"} & set(evidence["transform_ops"])
        )
        has_byte_buffer_shape = evidence["byte_memory_ops"] >= 3
        if (
            evidence["transform_ops"]
            and evidence["memory_reads"]
            and evidence["memory_writes"]
            and (has_strong_transform or has_byte_buffer_shape)
        ):
            transform_loops.append(
                {
                    "back_edge": edge,
                    "start": hex(blocks[loop_start].start),
                    "end": hex(blocks[loop_end].end),
                    "classification": "probable_byte_transform_loop",
                    "evidence": evidence,
                }
            )

    return {
        "block_count": len(blocks),
        "edge_count": len(edges),
        "loop_count": len(loop_edges),
        "loop_edges": loop_edges[:20],
        "probable_transform_loops": transform_loops[:20],
    }


def loop_transform_evidence(insns) -> dict[str, Any]:
    facts = [instruction_fact(insn) for insn in insns]
    transform_ops = sorted({fact.transform_op for fact in facts if fact.transform_op})
    return {
        "transform_ops": transform_ops,
        "memory_reads": sum(fact.memory_reads for fact in facts),
        "memory_writes": sum(fact.memory_writes for fact in facts),
        "byte_memory_ops": sum(fact.byte_memory_ops for fact in facts),
    }


def instruction_fact(insn) -> InstructionFact:
    mnemonic = insn.mnemonic.lower()
    operands = insn.operands
    group = getattr(insn, "group", None)
    is_jump = bool(group and group(X86_GRP_JUMP))
    target = None
    if is_jump and operands and operands[0].type == X86_OP_IMM:
        target = int(operands[0].imm)

    memory_reads = 0
    memory_writes = 0
    byte_memory_ops = 0
    if operands:
        writes_memory = operands[0].type == X86_OP_MEM
        reads_memory = False
        for operand in operands:
            if operand.type != X86_OP_MEM:
                continue
            if getattr(operand, "size", 0) == 1:
                byte_memory_ops = 1
            if operand is not operands[0]:
                reads_memory = True
        if writes_memory and mnemonic in READ_MODIFY_WRITE_MNEMONICS:
            reads_memory = True
        memory_reads = int(reads_memory)
        memory_writes = int(writes_memory)

    return InstructionFact(
        address=insn.address,
        size=getattr(insn, "size", 0),
        mnemonic=mnemonic,
        branch_target=target,
        is_conditional_jump=is_jump and mnemonic != "jmp",
        memory_reads=memory_reads,
        memory_writes=memory_writes,
        byte_memory_ops=byte_memory_ops,
        transform_op=mnemonic if mnemonic in TRANSFORM_MNEMONICS else None,
    )


def fact_prefixes(facts: list[InstructionFact]) -> dict[str, Any]:
    memory_reads = [0]
    memory_writes = [0]
    byte_memory_ops = [0]
    transform_ops = {op: [0] for op in TRANSFORM_MNEMONICS}
    for fact in facts:
        memory_reads.append(memory_reads[-1] + fact.memory_reads)
        memory_writes.append(memory_writes[-1] + fact.memory_writes)
        byte_memory_ops.append(byte_memory_ops[-1] + fact.byte_memory_ops)
        for op, values in transform_ops.items():
            values.append(values[-1] + int(fact.transform_op == op))
    return {
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
        "byte_memory_ops": byte_memory_ops,
        "transform_ops": transform_ops,
    }


def loop_transform_evidence_from_prefix(prefixes: dict[str, Any], start: int, end: int) -> dict[str, Any]:
    transform_ops = sorted(
        op
        for op, values in prefixes["transform_ops"].items()
        if values[end] - values[start]
    )
    return {
        "transform_ops": transform_ops,
        "memory_reads": prefixes["memory_reads"][end] - prefixes["memory_reads"][start],
        "memory_writes": prefixes["memory_writes"][end] - prefixes["memory_writes"][start],
        "byte_memory_ops": prefixes["byte_memory_ops"][end] - prefixes["byte_memory_ops"][start],
    }


def branch_target(insn) -> int | None:
    if not insn.group(X86_GRP_JUMP):
        return None
    if not insn.operands or insn.operands[0].type != X86_OP_IMM:
        return None
    return int(insn.operands[0].imm)


def is_conditional_jump(insn) -> bool:
    mnemonic = insn.mnemonic.lower()
    return insn.group(X86_GRP_JUMP) and mnemonic != "jmp"


def function_by_name(analyzer: Any, name: str) -> dict[str, Any] | None:
    if name in analyzer.user_by_name:
        return analyzer.user_by_name[name]
    for function in analyzer.user_functions:
        if function.get("FullName") == name:
            return function
    return None


def empty_cfg_summary() -> dict[str, Any]:
    return {
        "block_count": 0,
        "edge_count": 0,
        "loop_count": 0,
        "loop_edges": [],
        "probable_transform_loops": [],
    }


def summarize_cfg(functions: dict[str, Any]) -> dict[str, int]:
    summary = {
        "function_count": len(functions),
        "block_count": 0,
        "edge_count": 0,
        "loop_count": 0,
        "probable_transform_loop_count": 0,
    }
    for facts in functions.values():
        summary["block_count"] += facts.get("block_count", 0)
        summary["edge_count"] += facts.get("edge_count", 0)
        summary["loop_count"] += facts.get("loop_count", 0)
        summary["probable_transform_loop_count"] += len(facts.get("probable_transform_loops", []))
    return summary
