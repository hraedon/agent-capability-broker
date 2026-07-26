"""Qualified launcher contract: request/result schemas for WI-3.2.

A qualified launcher is the component-owned executable that ``acb exec``
injects credentials into on a Windows (or POSIX) execution host.  ACB owns
capability resolution, exact ``trusted_argv`` matching, minimal environment
injection, timeout/process-tree containment, and value-free provenance.  The
launcher owns creation of the authenticated process, the operation allowlist,
rollback, and evidence reduction.

This module publishes the *contract* — the schemas a conforming launcher must
accept and produce — plus a fake launcher usable as a conformance fixture in
CI.  The real launcher lives in the consuming component (initially
windows-evidence-lab); ACB never implements product operations.

Schemas are plain JSON dicts validated by the functions here.  No third-party
dependency is introduced.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

LAUNCHER_REQUEST_SCHEMA = "acb.launcher-request.v1"
LAUNCHER_RESULT_SCHEMA = "acb.launcher-result.v1"

_RESULT_STATUSES = frozenset({"success", "failure", "authorization_denied"})


@dataclass(frozen=True)
class LauncherRequest:
    """What ACB hands a qualified launcher via environment.

    The launcher receives:
    - Injected credential fields as environment variables (names from the
      manifest ``inject`` mapping).
    - ``ACB_CHECKOUT_RECEIPT``: the ``acb.checkout-receipt.v1`` JSON correlating
      this invocation.

    This dataclass is the *parsed* view a launcher should construct from its
    environment at startup.
    """

    invocation_id: str
    capability_id: str
    fields: dict[str, str]
    receipt_raw: str

    @classmethod
    def from_environ(
        cls,
        env: dict[str, str] | None = None,
        *,
        expected_capability_id: str | None = None,
    ) -> LauncherRequest:
        """Parse the launcher request from the child environment.

        When ``expected_capability_id`` is given, the receipt's capability must
        match — a misconfigured launcher serving the wrong capability fails
        closed.  Raises ``ValueError`` with a redacted message when the
        environment is not a valid ACB-injected launcher context.
        """
        env = env if env is not None else dict(os.environ)
        receipt_raw = env.get("ACB_CHECKOUT_RECEIPT")
        if not receipt_raw:
            raise ValueError("ACB_CHECKOUT_RECEIPT is not set")
        try:
            receipt = json.loads(receipt_raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("ACB_CHECKOUT_RECEIPT is not valid JSON") from exc
        if receipt.get("schema") != "acb.checkout-receipt.v1":
            raise ValueError("ACB_CHECKOUT_RECEIPT has an unexpected schema")
        invocation_id = receipt.get("invocation_id")
        if not isinstance(invocation_id, str) or not invocation_id:
            raise ValueError("receipt is missing invocation_id")
        checkouts = receipt.get("checkouts")
        if not isinstance(checkouts, list) or len(checkouts) != 1:
            raise ValueError("receipt must contain exactly one checkout")
        checkout = checkouts[0]
        capability_id = checkout.get("capability_id")
        if not isinstance(capability_id, str) or not capability_id:
            raise ValueError("checkout is missing capability_id")
        if (
            expected_capability_id is not None
            and capability_id != expected_capability_id
        ):
            raise ValueError(
                f"receipt capability {capability_id!r} does not match "
                f"expected {expected_capability_id!r}"
            )
        field_map = checkout.get("fields")
        if not isinstance(field_map, dict) or not field_map:
            raise ValueError("checkout is missing fields mapping")
        fields: dict[str, str] = {}
        for semantic_field, env_name in field_map.items():
            value = env.get(env_name)
            if value is None:
                raise ValueError(
                    f"field {semantic_field!r} maps to {env_name!r} which is not set"
                )
            fields[semantic_field] = value
        return cls(
            invocation_id=invocation_id,
            capability_id=capability_id,
            fields=fields,
            receipt_raw=receipt_raw,
        )


@dataclass(frozen=True)
class OperationResult:
    """One allowlisted operation the launcher performed."""

    operation: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class LauncherResult:
    """What a qualified launcher writes to stdout as its terminal output.

    The result is a single JSON object on stdout.  It must never contain a
    resolved credential value.  The consuming component defines operation
    semantics; ACB validates only the envelope shape.
    """

    invocation_id: str
    status: str
    operations: tuple[OperationResult, ...] = ()
    evidence_hash: str = ""
    cleanup_verified: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in _RESULT_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_RESULT_STATUSES)}, got {self.status!r}"
            )

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": LAUNCHER_RESULT_SCHEMA,
                "invocation_id": self.invocation_id,
                "status": self.status,
                "operations": [
                    {"operation": op.operation, "status": op.status, "detail": op.detail}
                    for op in self.operations
                ],
                "evidence_hash": self.evidence_hash,
                "cleanup_verified": self.cleanup_verified,
                "detail": self.detail,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str) -> LauncherResult:
        """Parse and validate a launcher result from its JSON text.

        Raises ``ValueError`` on any shape violation.
        """
        try:
            data: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("launcher result is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("launcher result must be a JSON object")
        if data.get("schema") != LAUNCHER_RESULT_SCHEMA:
            raise ValueError(
                f"launcher result schema must be {LAUNCHER_RESULT_SCHEMA!r}"
            )
        invocation_id = data.get("invocation_id")
        if not isinstance(invocation_id, str) or not invocation_id:
            raise ValueError("launcher result is missing invocation_id")
        status = data.get("status")
        if not isinstance(status, str) or status not in _RESULT_STATUSES:
            raise ValueError(
                f"launcher result status must be one of {sorted(_RESULT_STATUSES)}"
            )
        raw_ops = data.get("operations", [])
        if not isinstance(raw_ops, list):
            raise ValueError("launcher result operations must be a list")
        operations: list[OperationResult] = []
        for entry in raw_ops:
            if not isinstance(entry, dict):
                raise ValueError("each operation must be a JSON object")
            op_name = entry.get("operation")
            op_status = entry.get("status")
            if not isinstance(op_name, str) or not op_name:
                raise ValueError("operation is missing a name")
            if not isinstance(op_status, str) or not op_status:
                raise ValueError("operation is missing a status")
            operations.append(
                OperationResult(
                    operation=op_name,
                    status=op_status,
                    detail=str(entry.get("detail", "")),
                )
            )
        evidence_hash = data.get("evidence_hash", "")
        if not isinstance(evidence_hash, str):
            raise ValueError("evidence_hash must be a string")
        cleanup_verified = data.get("cleanup_verified", False)
        if not isinstance(cleanup_verified, bool):
            raise ValueError("cleanup_verified must be a boolean")
        detail = data.get("detail", "")
        if not isinstance(detail, str):
            raise ValueError("detail must be a string")
        return cls(
            invocation_id=invocation_id,
            status=status,
            operations=tuple(operations),
            evidence_hash=evidence_hash,
            cleanup_verified=cleanup_verified,
            detail=detail,
        )


__all__ = [
    "LAUNCHER_REQUEST_SCHEMA",
    "LAUNCHER_RESULT_SCHEMA",
    "LauncherRequest",
    "LauncherResult",
    "OperationResult",
]
