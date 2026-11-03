"""Exercise onboarding through the real optional HVAC client, without network I/O."""

from __future__ import annotations

import json
from typing import Any

import pytest

hvac = pytest.importorskip("hvac")
requests = pytest.importorskip("requests")

from agent_capability_broker.onboard import (  # noqa: E402
    OnboardAction,
    _apply_policy,
    _unwind,
    probe_policy,
)


class SyntheticTransport(requests.adapters.BaseAdapter):
    def __init__(self, read_status: int = 200) -> None:
        super().__init__()
        self.read_status = read_status
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.delete_status = 204

    def send(self, request: Any, **kwargs: Any) -> Any:
        body = json.loads(request.body) if request.body else None
        self.calls.append((request.method, request.url, body))
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = (
            self.read_status
            if request.method == "GET"
            else self.delete_status
            if request.method == "DELETE"
            else 204
        )
        response.headers["Content-Type"] = "application/json"
        response._content = (
            json.dumps(
                {"data": {"name": "sample-policy", "policy": 'path \\"sample\\" {}'}}
            ).encode()
            if response.status_code == 200
            else json.dumps({"errors": ["synthetic failure"]}).encode()
            if response.status_code != 204
            else b""
        )
        return response

    def close(self) -> None:
        pass


def client_for(status: int = 200) -> tuple[Any, SyntheticTransport]:
    session = requests.Session()
    transport = SyntheticTransport(status)
    session.mount("https://vault.example/", transport)
    return hvac.Client(url="https://vault.example", token="synthetic", session=session), transport


def test_read_acl_policy_uses_modern_path_and_nested_policy() -> None:
    client, transport = client_for()
    result = probe_policy(client, "sample-policy")
    assert result.present is True
    assert result.data == {"hcl": 'path \\"sample\\" {}'}
    assert transport.calls == [
        ("GET", "https://vault.example/v1/sys/policies/acl/sample-policy", None)
    ]


@pytest.mark.parametrize(
    ("status", "present", "reason"), [(404, False, ""), (403, None, "permission denied")]
)
def test_real_hvac_classifies_absent_and_denied(
    status: int, present: bool | None, reason: str
) -> None:
    client, transport = client_for(status)
    result = probe_policy(client, "sample-policy")
    assert (result.present, result.reason) == (present, reason)
    assert transport.calls[0][1].endswith("/v1/sys/policies/acl/sample-policy")


def test_create_and_rollback_use_modern_policy_endpoint() -> None:
    client, transport = client_for(404)
    action = OnboardAction(
        capability="cred:sample", kind="create_policy", target="sample-policy", summary="fixture"
    )
    undo: list[Any] = []
    result = _apply_policy(client, action, "sample-policy", "path sample {}", undo)
    assert result.status == "applied"
    assert [row.status for row in _unwind(undo)] == ["rolled_back"]
    assert transport.calls == [
        ("GET", "https://vault.example/v1/sys/policies/acl/sample-policy", None),
        (
            "PUT",
            "https://vault.example/v1/sys/policies/acl/sample-policy",
            {"policy": "path sample {}"},
        ),
        ("DELETE", "https://vault.example/v1/sys/policies/acl/sample-policy", None),
    ]


def test_denied_read_never_registers_delete_rollback() -> None:
    client, transport = client_for(403)
    action = OnboardAction(
        capability="cred:sample", kind="create_policy", target="sample-policy", summary="fixture"
    )
    undo: list[Any] = []
    result = _apply_policy(client, action, "sample-policy", "path sample {}", undo)
    assert result.status == "applied"
    assert "prior state could not be read" in result.detail
    assert _unwind(undo) == []
    assert [call[0] for call in transport.calls] == ["GET", "PUT"]


def test_forbidden_rollback_reports_failure_without_exposing_response() -> None:
    client, transport = client_for(404)
    transport.delete_status = 403
    action = OnboardAction(
        capability="cred:sample", kind="create_policy", target="sample-policy", summary="fixture"
    )
    undo: list[Any] = []
    assert (
        _apply_policy(client, action, "sample-policy", "path sample {}", undo).status == "applied"
    )
    result = _unwind(undo)
    assert len(result) == 1 and result[0].status == "rollback_failed"
    assert "Forbidden" in result[0].detail
    assert "synthetic failure" not in result[0].detail
    assert transport.calls[-1][:2] == (
        "DELETE",
        "https://vault.example/v1/sys/policies/acl/sample-policy",
    )
