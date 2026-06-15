"""Harness adapters (read side). Stdlib-only.

Each adapter encapsulates one harness's config format and exposes a normalized
view (`McpServer`) so providers stay harness-agnostic. Read-only by charter:
nothing here writes a config or extracts a secret value — only the fields needed
to decide whether a capability is wired (command/url/enabled), never headers or
tokens.
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import McpServer

_REMOTE_TYPES = {"remote", "http", "sse"}


def _load_json(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _normalize(name: str, entry: dict[str, object]) -> McpServer:
    """Map a single harness MCP entry to the normalized view."""
    url = entry.get("url")
    url = url if isinstance(url, str) else None

    raw_cmd = entry.get("command")
    if isinstance(raw_cmd, list):  # opencode: command is already argv
        command = tuple(str(x) for x in raw_cmd)
    elif isinstance(raw_cmd, str):  # claude: command + separate args
        args = entry.get("args")
        arglist = [str(x) for x in args] if isinstance(args, list) else []
        command = (raw_cmd, *arglist)
    else:
        command = ()

    etype = entry.get("type")
    if (isinstance(etype, str) and etype.lower() in _REMOTE_TYPES) or (url and not command):
        kind = "remote"
    elif command:
        kind = "local"
    else:
        kind = "unknown"

    # opencode uses explicit `enabled`; claude has no such key (absent => on),
    # but honor a `disabled` flag if present.
    enabled = bool(entry.get("enabled", not entry.get("disabled", False)))

    return McpServer(name=name, kind=kind, command=command, url=url, enabled=enabled)


def _servers_from(table: object) -> dict[str, McpServer]:
    if not isinstance(table, dict):
        return {}
    out: dict[str, McpServer] = {}
    for name, entry in table.items():
        if isinstance(entry, dict):
            out[str(name)] = _normalize(str(name), entry)
    return out


class ClaudeAdapter:
    """Claude Code: `~/.claude/settings.json` -> `mcpServers`."""

    name = "claude"

    def __init__(self, settings_path: Path | None = None) -> None:
        self.settings_path = settings_path or (Path.home() / ".claude" / "settings.json")

    def available(self) -> bool:
        return self.settings_path.is_file()

    def mcp_servers(self) -> dict[str, McpServer]:
        return _servers_from(_load_json(self.settings_path).get("mcpServers"))


class OpencodeAdapter:
    """opencode: `~/.config/opencode/opencode.json` -> `mcp`."""

    name = "opencode"

    def __init__(self, config_path: Path | None = None) -> None:
        self.config_path = config_path or (
            Path.home() / ".config" / "opencode" / "opencode.json"
        )

    def available(self) -> bool:
        return self.config_path.is_file()

    def mcp_servers(self) -> dict[str, McpServer]:
        return _servers_from(_load_json(self.config_path).get("mcp"))
