from typing import Any

from capstone.x86 import *


TRANSFORM_MNEMONICS = {"xor", "add", "sub", "rol", "ror", "not"}
MAX_CFG_INSTRUCTIONS = 50000
MAX_LOOP_INSTRUCTIONS = 8000


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

    starts = {insns[0].address}
    branch_targets = set()
    for index, insn in enumerate(insns):
        target = branch_target(insn)
        if target is not None and function["Start"] <= target < function["End"]:
            branch_targets.add(target)
            starts.add(target)
            if index + 1 < len(insns):
                starts.add(insns[index + 1].address)

    sorted_starts = sorted(starts)
    address_to_index = {insn.address: index for index, insn in enumerate(insns)}
    block_for_address = {}
    blocks = []
    for index, start in enumerate(sorted_starts):
        end = sorted_starts[index + 1] if index + 1 < len(sorted_starts) else function["End"]
        start_index = address_to_index.get(start)
        if start_index is None:
            continue
        end_index = address_to_index.get(end, len(insns))
        block_insns = insns[start_index:end_index]
        if not block_insns:
            continue
        block_id = f"{function_name}:block_{len(blocks)}"
        for insn in block_insns:
            block_for_address[insn.address] = block_id
        blocks.append(
            {
                "id": block_id,
                "start": block_insns[0].address,
                "end": block_insns[-1].address + block_insns[-1].size,
                "instructions": block_insns,
            }
        )

    edges = []
    loop_edges = []
    for index, block in enumerate(blocks):
        last = block["instructions"][-1]
        target = branch_target(last)
        if target is not None and target in block_for_address:
            edge = {
                "from": block["id"],
                "to": block_for_address[target],
                "type": "jump",
                "instruction": hex(last.address),
            }
            edges.append(edge)
            if target <= block["start"]:
                loop_edges.append(edge)
        if is_conditional_jump(last) and index + 1 < len(blocks):
            edges.append(
                {
                    "from": block["id"],
                    "to": blocks[index + 1]["id"],
                    "type": "fallthrough",
                    "instruction": hex(last.address),
                }
            )

    transform_loops = []
    for edge in loop_edges:
        loop_start = int(edge["to"].split("_")[-1])
        loop_end = int(edge["from"].split("_")[-1])
        if loop_start > loop_end or loop_end >= len(blocks):
            continue
        loop_instruction_count = sum(
            len(block["instructions"]) for block in blocks[loop_start : loop_end + 1]
        )
        if loop_instruction_count > MAX_LOOP_INSTRUCTIONS:
            continue
        loop_insns = []
        for block in blocks[loop_start : loop_end + 1]:
            loop_insns.extend(block["instructions"])
        evidence = loop_transform_evidence(loop_insns)
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
                    "start": hex(blocks[loop_start]["start"]),
                    "end": hex(blocks[loop_end]["end"]),
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
    transform_ops = sorted({insn.mnemonic.lower() for insn in insns if insn.mnemonic.lower() in TRANSFORM_MNEMONICS})
    memory_reads = 0
    memory_writes = 0
    byte_memory_ops = 0
    for insn in insns:
        if any(operand.type == X86_OP_MEM for operand in insn.operands[1:]):
            memory_reads += 1
        if insn.operands and insn.operands[0].type == X86_OP_MEM:
            memory_writes += 1
        if any(operand.type == X86_OP_MEM and getattr(operand, "size", 0) == 1 for operand in insn.operands):
            byte_memory_ops += 1
    return {
        "transform_ops": transform_ops,
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
        "byte_memory_ops": byte_memory_ops,
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
