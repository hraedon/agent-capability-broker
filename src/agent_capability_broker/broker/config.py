"""Broker view of the manifest: the v2 keys ``acb-broker`` needs. Stdlib-only.

TODO(WI-012-2 follow-up): switch to the shared manifest-v2 model once WI-012-2
lands its ``issuer`` / ``delivery`` / ``assurance`` / ``harnesses`` parsing in
``model.py``. Until then this module keeps its own minimal parser over the raw
TOML, located with the existing ``model.resolve_manifest`` precedence.

Only capabilities that declare an ``issuer`` table are served by the broker;
v1 entries (no ``issuer``) are ignored here — they keep today's ``acb exec``
semantics. A malformed v2 entry is a hard error: the broker refuses to start
rather than serve a half-understood manifest.

No value ever lives in the manifest; this module reads names, paths and
policy only.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..model import ManifestError, resolve_manifest

ISSUER_KINDS = frozenset({"fake", "vault-kv", "vault-k8s-token", "remote-mint"})
RUNGS = frozenset({"helper", "proxy", "remote-op", "env"})
ASSURANCE_LEVELS = frozenset({"D0", "D1", "H1", "H1+D1"})
#: The assurance an issuer kind can actually deliver from inside the VM.
#: A static KV read is D0 by definition (Plan 012 §2).
ISSUER_ASSURANCE = {
    "fake": "D1",
    "vault-kv": "D0",
    "vault-k8s-token": "D1",
    "remote-mint": "D1",
}
_RANK = {"D0": 0, "D1": 1, "H1": 2, "H1+D1": 3}
#: Plan 012 §6: anything the broker hands out lives at most 15 minutes.
MAX_TTL_SECONDS = 15 * 60
DEFAULT_TTL_SECONDS = MAX_TTL_SECONDS

_TTL_RE = re.compile(r"^(\d+)\s*([smh]?)$")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600}


class BrokerConfigError(ManifestError):
    """A v2 capability the broker cannot serve as declared. Message is value-free."""


def parse_ttl(raw: object, *, where: str) -> int:
    """``900`` / ``"900s"`` / ``"15m"`` -> seconds, bounded by ``MAX_TTL_SECONDS``."""
    if isinstance(raw, bool):
        raise BrokerConfigError(f"{where}: ttl must be seconds or a '15m'-style string")
    if isinstance(raw, int):
        seconds = raw
    elif isinstance(raw, str) and (m := _TTL_RE.match(raw.strip())):
        seconds = int(m.group(1)) * _UNIT[m.group(2)]
    else:
        raise BrokerConfigError(f"{where}: ttl must be seconds or a '15m'-style string")
    if not 1 <= seconds <= MAX_TTL_SECONDS:
        raise BrokerConfigError(
            f"{where}: ttl {seconds}s is outside 1..{MAX_TTL_SECONDS}s (Plan 012 §6: <= 15m)"
        )
    return seconds


@dataclass(frozen=True)
class IssuerSpec:
    kind: str
    ttl: int
    params: dict[str, Any] = field(default_factory=dict)  # kind-specific, value-free


@dataclass(frozen=True)
class DeliverySpec:
    rung: str
    tool: str | None = None
    hosts: tuple[str, ...] = ()
    username: str | None = None


@dataclass(frozen=True)
class BrokerCapability:
    id: str
    provider: str
    issuer: IssuerSpec
    delivery: DeliverySpec
    assurance: str                 # declared floor
    harnesses: tuple[str, ...]     # advisory allowlist; empty = any

    @property
    def effective_assurance(self) -> str:
        """What the issuer can actually deliver (may be below the declared floor)."""
        return ISSUER_ASSURANCE[self.issuer.kind]

    @property
    def meets_floor(self) -> bool:
        return _RANK[self.effective_assurance] >= _RANK[self.assurance]


@dataclass(frozen=True)
class BrokerConfig:
    source: Path | None
    capabilities: dict[str, BrokerCapability]

    def match(self, tool: str, host: str | None) -> BrokerCapability | None:
        """The capability whose helper delivery serves ``tool`` (and ``host``)."""
        want = host.lower() if host else None
        for cap in self.capabilities.values():
            d = cap.delivery
            if d.rung != "helper" or d.tool != tool:
                continue
            if d.hosts:
                if want is not None and want in d.hosts:
                    return cap
            elif want is None:
                return cap
        return None


def _str_list(raw: object, *, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
        raise BrokerConfigError(f"{where}: must be a list of non-empty strings")
    return tuple(raw)


def _req_str(table: dict[str, Any], key: str, *, where: str) -> str:
    val = table.get(key)
    if not isinstance(val, str) or not val:
        raise BrokerConfigError(f"{where}: {key!r} is required and must be a non-empty string")
    return val


def _vault_segment(val: str, *, where: str, key: str) -> str:
    if val.startswith("/") or val.endswith("/") or ".." in val.split("/") or "\\" in val:
        raise BrokerConfigError(f"{where}: {key!r} must be a relative Vault path segment")
    return val


def _parse_issuer(cap_id: str, raw: object) -> IssuerSpec:
    where = f"capability {cap_id!r} issuer"
    if not isinstance(raw, dict):
        raise BrokerConfigError(f"{where}: must be a table")
    kind = raw.get("kind")
    if kind not in ISSUER_KINDS:
        raise BrokerConfigError(f"{where}: unknown kind {kind!r} (known: {sorted(ISSUER_KINDS)})")
    ttl = parse_ttl(raw["ttl"], where=where) if "ttl" in raw else DEFAULT_TTL_SECONDS
    params = {k: v for k, v in raw.items() if k not in {"kind", "ttl"}}
    if kind == "vault-kv":
        path = _vault_segment(_req_str(raw, "path", where=where), where=where, key="path")
        if "/" not in path:
            raise BrokerConfigError(f"{where}: 'path' must be '<mount>/<path>'")
        if "fields" in raw:
            params["fields"] = list(_str_list(raw["fields"], where=f"{where} fields"))
        elif "field" in raw:
            params["fields"] = [_req_str(raw, "field", where=where)]
            params.pop("field")
        else:
            # Same fail-closed rule as cred_vault.resolve: no "all fields" default.
            raise BrokerConfigError(f"{where}: field selection required ('fields' or 'field')")
    elif kind == "vault-k8s-token":
        _vault_segment(_req_str(raw, "role", where=where), where=where, key="role")
        _req_str(raw, "namespace", where=where)
        params["mount"] = _vault_segment(
            str(raw.get("mount", "kubernetes")), where=where, key="mount"
        )
        if "audiences" in raw:
            params["audiences"] = list(_str_list(raw["audiences"], where=f"{where} audiences"))
        if "cluster_role_binding" in raw and not isinstance(raw["cluster_role_binding"], bool):
            raise BrokerConfigError(f"{where}: 'cluster_role_binding' must be a boolean")
    return IssuerSpec(kind=str(kind), ttl=ttl, params=params)


def _parse_delivery(cap_id: str, raw: object) -> DeliverySpec:
    where = f"capability {cap_id!r} delivery"
    if raw is None:
        return DeliverySpec(rung="env")
    if not isinstance(raw, dict):
        raise BrokerConfigError(f"{where}: must be a table")
    rung = raw.get("rung")
    if rung not in RUNGS:
        raise BrokerConfigError(f"{where}: rung must be one of {sorted(RUNGS)}")
    tool = raw.get("tool")
    if tool is not None and (not isinstance(tool, str) or not tool):
        raise BrokerConfigError(f"{where}: 'tool' must be a non-empty string")
    hosts = _str_list(raw["hosts"], where=f"{where} hosts") if "hosts" in raw else ()
    username = raw.get("username")
    if username is not None and (not isinstance(username, str) or not username):
        raise BrokerConfigError(f"{where}: 'username' must be a non-empty string")
    if rung == "helper" and tool is None:
        raise BrokerConfigError(f"{where}: rung 'helper' needs a 'tool'")
    return DeliverySpec(
        rung=str(rung),
        tool=tool,
        hosts=tuple(h.lower() for h in hosts),
        username=username,
    )


def parse_broker_config(raw: dict[str, Any], *, source: Path | None = None) -> BrokerConfig:
    """Pick out and validate the broker-served (``issuer``-bearing) capabilities."""
    table = raw.get("capability", {})
    if not isinstance(table, dict):
        raise BrokerConfigError("manifest 'capability' must be a table")
    caps: dict[str, BrokerCapability] = {}
    git_hosts: dict[str, str] = {}
    for cap_id, body in table.items():
        if not isinstance(body, dict) or "issuer" not in body:
            continue
        provider = body.get("provider")
        if not isinstance(provider, str) or not provider:
            raise BrokerConfigError(f"capability {cap_id!r}: 'provider' is required")
        issuer = _parse_issuer(cap_id, body["issuer"])
        delivery = _parse_delivery(cap_id, body.get("delivery"))
        assurance = body.get("assurance", ISSUER_ASSURANCE[issuer.kind])
        if assurance not in ASSURANCE_LEVELS:
            raise BrokerConfigError(
                f"capability {cap_id!r}: assurance must be one of {sorted(ASSURANCE_LEVELS)}"
            )
        harnesses = (
            _str_list(body["harnesses"], where=f"capability {cap_id!r} harnesses")
            if "harnesses" in body
            else ()
        )
        if delivery.rung == "helper" and delivery.tool == "git":
            for host in delivery.hosts:
                if host in git_hosts:
                    raise BrokerConfigError(
                        f"capability {cap_id!r}: git host {host!r} is already served by "
                        f"{git_hosts[host]!r} (one capability per host)"
                    )
                git_hosts[host] = cap_id
        caps[cap_id] = BrokerCapability(
            id=cap_id,
            provider=provider,
            issuer=issuer,
            delivery=delivery,
            assurance=str(assurance),
            harnesses=harnesses,
        )
    return BrokerConfig(source=source, capabilities=caps)


def load_broker_config(manifest: str | os.PathLike[str] | None = None) -> BrokerConfig:
    """Resolve the manifest (same precedence as every other verb) and parse it."""
    path = resolve_manifest(manifest)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BrokerConfigError(f"cannot read manifest {path}: {exc}") from exc
    return parse_broker_config(raw, source=path)


__all__ = [
    "ASSURANCE_LEVELS",
    "DEFAULT_TTL_SECONDS",
    "ISSUER_ASSURANCE",
    "ISSUER_KINDS",
    "MAX_TTL_SECONDS",
    "RUNGS",
    "BrokerCapability",
    "BrokerConfig",
    "BrokerConfigError",
    "DeliverySpec",
    "IssuerSpec",
    "load_broker_config",
    "parse_broker_config",
    "parse_ttl",
]
