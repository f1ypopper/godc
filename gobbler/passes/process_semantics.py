"""Neutral process API semantics shared by graph and argument projections."""
from __future__ import annotations

import re


# Match complete Go symbols (including common compiler wrappers), not substrings
# such as a user-defined CommandPreview or Cmd.Runner method.
COMMAND_RE = re.compile(r"^(?:os/)?exec\.command(?:context)?(?:\.abi0|-fm)?$", re.I)
CMD_EXECUTION_RE = re.compile(
    r"^(?:os/)?exec\.(?:\(\*?cmd\)|cmd)\.(?:start|run|output|combinedoutput)(?:\.abi0|-fm)?$",
    re.I,
)
DIRECT_PROCESS_APIS = {
    "os.startprocess", "syscall.exec", "syscall.forkexec", "syscall.startprocess",
    "syscall.createprocess", "syscall.createprocessasuser",
    "windows.createprocess", "windows.createprocessasuser", "windows.shellexecute",
    "golang.org/x/sys/windows.createprocess", "golang.org/x/sys/windows.createprocessasuser",
    "golang.org/x/sys/windows.shellexecute", "createprocess", "createprocessa", "createprocessw",
    "shellexecute", "shellexecutea", "shellexecutew", "winexec", "execve", "posix_spawn",
}


def classify_process_api(target: object) -> str | None:
    if not isinstance(target, str):
        return None
    if COMMAND_RE.fullmatch(target):
        return "command_constructed"
    if CMD_EXECUTION_RE.fullmatch(target):
        return "process_start_attempt"
    if target.lower().removesuffix(".abi0") in DIRECT_PROCESS_APIS:
        return "process_start_attempt"
    return None


def is_cmd_execution(target: object) -> bool:
    return isinstance(target, str) and CMD_EXECUTION_RE.fullmatch(target) is not None
