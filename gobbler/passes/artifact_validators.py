from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit


CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/][^<>:\"|?*\x00-\x1f]{1,240}$")
WINDOWS_UNC_RE = re.compile(r"^\\\\[^\\/:*?\"<>|\s]+\\[^\\/:*?\"<>|\s]+(?:\\[^<>:\"|?*\x00-\x1f]{1,200})*$")
POSIX_ABSOLUTE_RE = re.compile(r"^/(?:[^\x00/\s]+/)*[^\x00/\s]*$")
EXPLICIT_RELATIVE_RE = re.compile(r"^\.\.?/(?:[^\x00/\s]+/)*[^\x00/\s]+$")
PLAIN_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,158}\.[A-Za-z0-9]{1,12}$")
HOST_RE = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
COMMAND_BASENAME_RE = re.compile(r"^[A-Za-z0-9_.+-]{2,80}(?:\.exe)?$")

GO_PATH_MARKERS = (
    "runtime.",
    "reflect.",
    "internal/",
    "vendor/",
    "golang.org/",
    "github.com/",
    "go/src/",
    "pkg/mod/",
)


def has_control_or_space_path_noise(value: str) -> bool:
    return bool(CONTROL_RE.search(value)) or "\n" in value or "\r" in value or "\t" in value


def strict_url(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if len(value) < 10 or len(value) > 2048:
        return False
    if CONTROL_RE.search(value) or any(ch.isspace() for ch in value):
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in GO_PATH_MARKERS):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    host = parsed.hostname
    if not host or len(host) > 253:
        return False
    if "_" in host or host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(HOST_RE.fullmatch(host))


def strict_host(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 253 or CONTROL_RE.search(value) or any(ch.isspace() for ch in value):
        return False
    host = value.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", value) else value
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(HOST_RE.fullmatch(host)) and not any(marker in host.lower() for marker in GO_PATH_MARKERS)


def strict_path(value: str, *, allow_plain_file: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip().strip("\"'")
    if len(value) < 2 or len(value) > 500:
        return False
    if has_control_or_space_path_noise(value):
        return False
    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        return False
    if any(marker in lowered for marker in GO_PATH_MARKERS):
        return False
    if any(marker in value for marker in ("%!s", "%!d", "%s", "%d", "${", "{{", "}}", "[", "]")):
        return False
    if WINDOWS_ABSOLUTE_RE.fullmatch(value) or WINDOWS_UNC_RE.fullmatch(value):
        return _valid_windows_path(value)
    if POSIX_ABSOLUTE_RE.fullmatch(value) or EXPLICIT_RELATIVE_RE.fullmatch(value):
        return _valid_posix_path(value)
    if allow_plain_file and PLAIN_FILE_RE.fullmatch(value):
        return True
    return False


def strict_file_argument(value: str) -> bool:
    return strict_path(value, allow_plain_file=True)


def strict_command(value: str, *, direct_exec_arg: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip().strip("\"'")
    if not value or len(value) > 260 or CONTROL_RE.search(value) or "\n" in value or "\r" in value:
        return False
    if strict_url(value):
        return False
    if strict_path(value, allow_plain_file=True):
        return True
    if any(ch.isspace() for ch in value):
        return False
    if value.startswith("-"):
        return direct_exec_arg
    return direct_exec_arg and bool(COMMAND_BASENAME_RE.fullmatch(value))


def command_argument_part(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 240 or CONTROL_RE.search(value):
        return False
    if value.startswith("-"):
        return len(value) <= 120 and not any(ch in value for ch in "\r\n\x00")
    if strict_url(value) or strict_path(value, allow_plain_file=True):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.:=,+/@%-]{1,160}", value))


def _valid_windows_path(value: str) -> bool:
    try:
        parts = PureWindowsPath(value).parts
    except Exception:
        return False
    return len(parts) >= 2 and all(part not in {"", ".", ".."} for part in parts[1:])


def _valid_posix_path(value: str) -> bool:
    try:
        parts = PurePosixPath(value).parts
    except Exception:
        return False
    if value.startswith(("./", "../")):
        return bool(parts) and all(part not in {"", "."} for part in parts)
    if len(parts) < 2:
        return False
    return not any(part in {"", "."} for part in parts[1:])
