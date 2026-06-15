"""Harness adapters (read side). Stdlib-only.

Each adapter encapsulates one harness's config format and exposes a normalized
view (`McpServer`) so providers stay harness-agnostic. Read-only by charter:
nothing here writes a config or extracts a secret value — only the fields needed
to decide whether a capability is wired (command/url/enabled), never headers or
tokens.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .model import McpServer


class WriteResult:
    """Outcome of a surgical config write (act path)."""

    def __init__(self, changed: bool, backup_path: Path | None) -> None:
        self.changed = changed
        self.backup_path = backup_path


def _backup(path: Path) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dest = path.with_name(f"{path.name}.bak-{ts}")
    dest.write_bytes(path.read_bytes())
    return dest


def _add_server(path: Path, container_key: str, name: str, entry: dict[str, object]) -> WriteResult:
    """Add a new MCP server under `container_key`, creating file/container as
    needed. Backs up an existing file first; refuses to clobber an existing
    server of the same name (callers check existence for idempotence)."""
    data = _load_json(path)
    container = data.get(container_key)
    if not isinstance(container, dict):
        container = {}
        data[container_key] = container
    if name in container:
        raise KeyError(f"server {name!r} already present in {container_key} of {path}")

    backup = _backup(path) if path.exists() else None
    container[name] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return WriteResult(changed=True, backup_path=backup)

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
        env = os.environ.get("ACB_CLAUDE_SETTINGS")
        self.settings_path = (
            settings_path
            or (Path(env) if env else Path.home() / ".claude" / "settings.json")
        )

    def available(self) -> bool:
        return self.settings_path.is_file()

    def mcp_servers(self) -> dict[str, McpServer]:
        return _servers_from(_load_json(self.settings_path).get("mcpServers"))

    def add_mcp_server(self, name: str, command: list[str]) -> WriteResult:
        """Add a stdio MCP server to Claude's `mcpServers` (command/args shape)."""
        entry: dict[str, object] = {"command": command[0], "args": list(command[1:])}
        return _add_server(self.settings_path, "mcpServers", name, entry)


class OpencodeAdapter:
    """opencode: `~/.config/opencode/opencode.json` -> `mcp`."""

    name = "opencode"

    def __init__(self, config_path: Path | None = None) -> None:
        env = os.environ.get("ACB_OPENCODE_CONFIG")
        self.config_path = (
            config_path
            or (Path(env) if env else Path.home() / ".config" / "opencode" / "opencode.json")
        )

    def available(self) -> bool:
        return self.config_path.is_file()

    def mcp_servers(self) -> dict[str, McpServer]:
        return _servers_from(_load_json(self.config_path).get("mcp"))

    def write_command(self, server: str, argv: list[str]) -> WriteResult:
        """Surgically set one MCP server's `command`, preserving everything else.

        Backs the file up first, is a no-op when already equal (idempotent), and
        only ever touches the targeted server's `command` key — so sibling
        servers (and any bearer tokens/headers they hold) survive byte-for-byte
        in value. Raises if the server is absent or the config is unparseable.
        """
        data = _load_json(self.config_path)
        mcp = data.get("mcp")
        if not isinstance(mcp, dict) or server not in mcp or not isinstance(mcp[server], dict):
            raise KeyError(f"opencode mcp server {server!r} not found in {self.config_path}")

        entry = mcp[server]
        if entry.get("command") == argv:
            return WriteResult(changed=False, backup_path=None)

        backup = _backup(self.config_path)
        entry["command"] = argv
        self.config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return WriteResult(changed=True, backup_path=backup)

    def add_mcp_server(self, name: str, command: list[str]) -> WriteResult:
        """Add a local MCP server to opencode's `mcp` (type/enabled/command shape)."""
        entry: dict[str, object] = {"type": "local", "enabled": True, "command": list(command)}
        return _add_server(self.config_path, "mcp", name, entry)
