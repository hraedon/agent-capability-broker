"""Manifest v2 keys, the lossless v1 upconvert, and the assurance derivation table.

Plan 012 §5 / WI-012-2. Pure parsing and derivation: no backend, no secrets.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from agent_capability_broker.model import (
    ASSURANCE_LEVELS,
    ISSUING_KINDS,
    STATIC_KINDS,
    BoundaryConfig,
    Capability,
    ManifestError,
    assurance_rank,
    derive_assurance,
    parse_boundary,
    parse_manifest,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "capabilities.example.toml"

# The four v1 entries that shipped in the example before v2 (they carry no v2 key).
V1_EXAMPLE_IDS = {"cred:svc-bot", "e2e:chromium", "cred:example-control", "cred:example-guest"}
V2_KEYS = {"issuer", "delivery", "assurance", "decision"}


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "capabilities.toml"
    p.write_text(body, encoding="utf-8")
    return p


def _cap(body: str, tmp_path: Path) -> Capability:
    head = '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n'
    path = _write(tmp_path, head + body)
    (cap,) = parse_manifest(path)
    return cap


# --- lossless v1 upconvert -------------------------------------------------------


def test_every_v1_example_upconverts_losslessly() -> None:
    raw = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))["capability"]
    caps = {c.id: c for c in parse_manifest(EXAMPLE)}
    assert V1_EXAMPLE_IDS <= set(caps), "the v1 examples must stay in the example manifest"
    for cap_id in V1_EXAMPLE_IDS:
        cap, table = caps[cap_id], raw[cap_id]
        assert not V2_KEYS & set(table), f"{cap_id} is meant to be a v1 entry"
        assert cap.delivery == {"rung": "env"}
        assert cap.rung == "env"
        assert cap.issuer is None
        assert cap.decision is None
        assert cap.declared_assurance is None
        assert cap.assurance == "D0"
        assert not cap.declares_v2
        # Lossless: every v1 key is still reachable exactly as before.
        assert cap.options == {k: v for k, v in table.items() if k not in {"provider", "harnesses"}}
        assert cap.harnesses == tuple(table["harnesses"])
        assert derive_assurance(cap)[0] == "D0"


def test_directly_constructed_capability_has_v1_defaults() -> None:
    cap = Capability(id="cred:x", provider="cred", harnesses=("claude",))
    assert cap.delivery == {"rung": "env"}
    assert cap.assurance == "D0"
    assert cap.issuer_kind is None


def test_v2_example_entries_parse() -> None:
    caps = {c.id: c for c in parse_manifest(EXAMPLE)}
    forge = caps["cred:forge-agent"]
    assert forge.issuer_kind == "remote-mint"
    assert forge.issuer is not None and forge.issuer["ttl"] == "15m"  # free-form keys kept
    assert forge.rung == "helper" and forge.delivery["tool"] == "git"
    assert forge.declared_assurance == "D1"
    assert forge.declares_v2
    ad = caps["cred:ad-query"]
    assert ad.rung == "remote-op" and ad.decision == "auto"
    assert ad.declared_assurance == "H1+D1"
    # v2 keys are first-class fields, not provider options.
    assert not V2_KEYS & set(forge.options)


def test_example_boundary_table() -> None:
    cfg = parse_boundary(EXAMPLE)
    assert cfg.vault_namespace == "example-vault"
    assert cfg.ssh_admin_targets == ("hypervisor-01.example.invalid",)


# --- validation ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ('issuer = "vault-ssh-ca"\n', "'issuer' must be a table"),
        ("issuer = { mount = \"ssh\" }\n", "issuer.kind is required"),
        ("issuer = { kind = 3 }\n", "issuer.kind is required"),
        ('issuer = { kind = "  " }\n', "issuer.kind is required"),
        ('delivery = "helper"\n', "'delivery' must be a table"),
        ("delivery = { tool = \"git\" }\n", "delivery.rung must be one of"),
        ('delivery = { rung = "carrier-pigeon" }\n', "delivery.rung must be one of"),
        ("delivery = { rung = 1 }\n", "delivery.rung must be one of"),
        ('assurance = "D2"\n', "assurance must be one of"),
        ("assurance = 1\n", "assurance must be one of"),
        ('assurance = "d1"\n', "assurance must be one of"),
        ('decision = "maybe"\n', "decision must be one of"),
        ("decision = true\n", "decision must be one of"),
        # decision is remote-op only: absent delivery (env), and every in-VM rung, refuse it.
        ('decision = "auto"\n', "only valid when delivery.rung = 'remote-op'"),
        ('decision = "approve"\ndelivery = { rung = "helper" }\n', "only valid when"),
        ('decision = "deny"\ndelivery = { rung = "proxy" }\n', "only valid when"),
        ('decision = "auto"\ndelivery = { rung = "env" }\n', "only valid when"),
    ],
)
def test_v2_validation_errors(tmp_path: Path, body: str, match: str) -> None:
    path = _write(
        tmp_path,
        f'[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n{body}',
    )
    with pytest.raises(ManifestError, match=match):
        parse_manifest(path)


@pytest.mark.parametrize("level", ASSURANCE_LEVELS)
def test_every_assurance_level_is_accepted(tmp_path: Path, level: str) -> None:
    assert _cap(f'assurance = "{level}"\n', tmp_path).declared_assurance == level


@pytest.mark.parametrize("decision", ["auto", "approve", "deny"])
def test_decision_accepted_on_remote_op(tmp_path: Path, decision: str) -> None:
    cap = _cap(f'decision = "{decision}"\ndelivery = {{ rung = "remote-op" }}\n', tmp_path)
    assert cap.decision == decision


@pytest.mark.parametrize("rung", ["helper", "proxy", "remote-op", "env"])
def test_every_rung_is_accepted_and_extra_keys_kept(tmp_path: Path, rung: str) -> None:
    cap = _cap(f'delivery = {{ rung = "{rung}", tool = "git", custom = [1, 2] }}\n', tmp_path)
    assert cap.rung == rung
    assert cap.delivery["custom"] == [1, 2]


def test_v1_keys_still_validate_as_before(tmp_path: Path) -> None:
    # A bad harness is still the existing error, untouched by the v2 code path.
    path = _write(tmp_path, '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["zsh"]\n')
    with pytest.raises(ManifestError, match="unknown harness"):
        parse_manifest(path)


# --- [boundary] ------------------------------------------------------------------


def test_boundary_absent_is_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n')
    assert parse_boundary(path) == BoundaryConfig()


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("vault_namespace = 3\n", "vault_namespace must be"),
        ('vault_namespace = "-n kube-system"\n', "vault_namespace must be"),
        ('vault_namespace = "Has_Upper"\n', "vault_namespace must be"),
        ('ssh_admin_targets = "host"\n', "ssh_admin_targets must be"),
        ("ssh_admin_targets = [1]\n", "ssh_admin_targets must be"),
        ('ssh_admin_targets = ["-oProxyCommand=x"]\n', "ssh_admin_targets must be"),
        ('vault_namespaces = "typo"\n', "unknown key"),
    ],
)
def test_boundary_validation(tmp_path: Path, body: str, match: str) -> None:
    path = _write(tmp_path, f"[boundary]\n{body}")
    with pytest.raises(ManifestError, match=match):
        parse_boundary(path)


def test_boundary_table_must_be_a_table(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="must be a table"):
        parse_boundary(_write(tmp_path, 'boundary = "x"\n'))


# --- assurance derivation table ---------------------------------------------------


def _derive(rung: str, kind: str | None) -> tuple[str, str]:
    issuer = {"kind": kind} if kind is not None else None
    cap = Capability(
        id="cred:x", provider="cred", harnesses=("claude",), issuer=issuer, delivery={"rung": rung}
    )
    return derive_assurance(cap)


@pytest.mark.parametrize("kind", sorted(ISSUING_KINDS))
@pytest.mark.parametrize("rung", ["helper", "proxy", "env"])
def test_in_vm_rung_with_issuing_kind_is_d1(rung: str, kind: str) -> None:
    assert _derive(rung, kind)[0] == "D1"


@pytest.mark.parametrize("kind", [None, *sorted(STATIC_KINDS), "gitea-token", "made-up"])
@pytest.mark.parametrize("rung", ["helper", "proxy", "env"])
def test_in_vm_rung_without_issuing_kind_is_d0(rung: str, kind: str | None) -> None:
    assert _derive(rung, kind)[0] == "D0"


@pytest.mark.parametrize("kind", sorted(ISSUING_KINDS))
def test_remote_op_with_issuing_kind_is_h1_d1(kind: str) -> None:
    assert _derive("remote-op", kind)[0] == "H1+D1"


@pytest.mark.parametrize("kind", [None, *sorted(STATIC_KINDS), "made-up"])
def test_remote_op_without_issuing_kind_is_h1(kind: str | None) -> None:
    assert _derive("remote-op", kind)[0] == "H1"


def test_issuing_and_static_kinds_are_the_documented_sets() -> None:
    assert ISSUING_KINDS == {
        "vault-ssh-ca",
        "vault-k8s-token",
        "vault-ldap-library",
        "vault-ldap-static",
        "vault-database",
        "vault-pki",
        "remote-mint",
    }
    assert STATIC_KINDS == {"vault-kv"}
    assert not ISSUING_KINDS & STATIC_KINDS


def test_derivation_reason_names_the_cause_and_is_deterministic() -> None:
    assert "not a known issuing kind" in _derive("helper", "made-up")[1]
    assert "static issuer 'vault-kv'" in _derive("env", "vault-kv")[1]
    assert "no issuer declared" in _derive("env", None)[1]
    assert _derive("helper", "vault-pki") == _derive("helper", "vault-pki")


def test_the_declared_floor_never_influences_the_derivation() -> None:
    def make(floor: str) -> Capability:
        return Capability(
            id="cred:x", provider="cred", harnesses=("claude",), declared_assurance=floor
        )

    low, high = make("D0"), make("H1+D1")
    assert derive_assurance(low) == derive_assurance(high)


def test_assurance_order() -> None:
    ranks = [assurance_rank(level) for level in ("D0", "D1", "H1", "H1+D1")]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4
