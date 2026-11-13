"""Standalone git credential helper: one scoped KV v2 read, no daemon or child.

The declaration shares the daemon's issuer/delivery parser. Only the selected
capability is used; harness and Vault plane selection belong to the caller.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import replace
from typing import IO, Never

from .broker.config import BrokerConfigError, DeliverySpec, _parse_delivery, _parse_issuer
from .broker.git_credential import _clean, parse_attributes
from .model import Capability, parse_manifest, resolve_manifest
from .secret_sources import SecretSourceConfigError, validate_cred_trusted_argv


class GitCredentialConfigError(SecretSourceConfigError):
    """The capability cannot be served by the standalone helper (exit 2)."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        # argparse normally echoes the supplied arguments in multi-line errors.
        raise GitCredentialConfigError("invalid git helper arguments")


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("capability", help="cred capability id (vault-kv, helper rung, tool git)")
    parser.add_argument("operation", choices=("get", "store", "erase"))
    parser.add_argument("-m", "--manifest", default=None, help="manifest path")


def main(argv: list[str]) -> int:
    """Keep even CLI usage failures inside the class-name-only error boundary."""
    parser = _Parser(prog="acb git-credential", description=__doc__)
    configure_parser(parser)
    try:
        args = parser.parse_args(argv)
    except GitCredentialConfigError as exc:
        print(type(exc).__name__, file=sys.stderr)
        return 2
    return run(args.capability, args.operation, args.manifest)


def _plain_host(host: str) -> bool:
    """A bare ASCII DNS name or IPv4 address; no ports, paths or URL syntax."""
    return len(host) <= 253 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label, re.IGNORECASE | re.ASCII)
        for label in host.split(".")
    )


def validate(cap: Capability) -> tuple[Capability, DeliverySpec]:
    """Return a KV resolver view and the shared delivery spec, without I/O.

    Use the daemon's existing ``issuer.path`` / ``issuer.fields`` and
    ``delivery.hosts`` shape, with one host and explicit secret field mappings.
    No duplicate top-level Vault declaration is needed.
    """
    if (
        cap.provider != "cred" or cap.options.get("source", "vault") != "vault"
        or cap.issuer_kind != "vault-kv" or cap.rung != "helper"
        or cap.delivery.get("tool") != "git"
    ):
        raise GitCredentialConfigError("expected a vault-kv git helper credential")
    try:
        issuer = _parse_issuer(cap.id, cap.issuer)
        delivery = _parse_delivery(cap.id, cap.delivery)
    except BrokerConfigError as exc:
        raise GitCredentialConfigError("invalid issuer or delivery") from exc
    if len(delivery.hosts) != 1 or not _plain_host(delivery.hosts[0]):
        raise GitCredentialConfigError("delivery.hosts must contain exactly one bare host")
    if delivery.username_field is None or delivery.password_field is None:
        raise GitCredentialConfigError("explicit username_field and password_field required")
    fields = issuer.params["fields"]
    if (
        delivery.username_field == delivery.password_field
        or set(fields) != {delivery.username_field, delivery.password_field}
        or len(fields) != 2
    ):
        raise GitCredentialConfigError("issuer.fields must select exactly the two mapped fields")
    # Prevent competing legacy declarations from changing the read or its grant
    # check. Both front-ends use issuer.path and issuer.fields exclusively.
    if any(key in cap.options for key in ("vault", "field", "fields")):
        raise GitCredentialConfigError("use issuer.path and issuer.fields only")
    resolver_cap = replace(cap, options={"vault": issuer.params["path"], "fields": fields})
    return resolver_cap, delivery


def run(
    cap_id: str, operation: str, manifest: str | None = None, *,
    stdin: IO[str] | None = None,
) -> int:
    """Git protocol entry point: 0 success/fallthrough, 1 runtime, 2 config.

    Build the complete answer before writing stdout. Failures report only an
    exception class, never attributes, configuration, backend text or values.
    """
    stream = sys.stdin if stdin is None else stdin
    try:
        if operation in {"store", "erase"}:
            # Consume git's request, including supplied credentials; never
            # resolve a manifest, log in, store, or revoke a standing secret.
            for line in stream:
                if line in {"\n", "\r\n"}:
                    break
            return 0
        if operation != "get":
            raise GitCredentialConfigError("unsupported operation")
        attrs = parse_attributes(stream, strict=True)
        caps = parse_manifest(resolve_manifest(manifest))
        cap = next((c for c in caps if c.id == cap_id), None)
        if cap is None:
            raise GitCredentialConfigError("capability not in manifest")
        resolver_cap, delivery = validate(cap)
        validate_cred_trusted_argv(cap)
        host = attrs.get("host", "")
        if (
            attrs.get("protocol") != delivery.protocol
            or not _plain_host(host) or host.lower() != delivery.hosts[0]
            or "port" in attrs or "path" in attrs or "url" in attrs
        ):
            return 0
        from . import cred_vault, provenance  # lazy optional [cred] backend
        from .model import Action, ActionResult

        assert delivery.username_field is not None and delivery.password_field is not None
        succeeded = False
        try:
            values = cred_vault.resolve(resolver_cap)
            username = _clean(values.get(delivery.username_field))
            password = _clean(values.get(delivery.password_field))
            if username is None or password is None:
                raise ValueError("invalid credential field")
            succeeded = True
        finally:
            # A value-free use event, including failed reads. Never include
            # request attributes, values, Vault paths or exception messages.
            provenance.emit(ActionResult(
                Action(cap.id, "", "git_credential", cap.id, "git helper read"),
                "applied" if succeeded else "failed",
            ), purpose="acb git-credential")
        sys.stdout.write(f"username={username}\npassword={password}\n")
        sys.stdout.flush()
        return 0
    except Exception as exc:
        print(type(exc).__name__, file=sys.stderr)
        from .model import ManifestError

        return 2 if isinstance(exc, (ManifestError, SecretSourceConfigError)) else 1
