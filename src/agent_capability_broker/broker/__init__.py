"""acb-broker: the in-VM credential broker (Plan 012 P1, WI-012-3).

Modules:

- ``protocol`` — ``acb.broker.v1`` framing, request validation, value rule.
- ``config`` — the manifest v2 keys the broker serves (own parser until WI-012-2).
- ``issuers`` — issuer interface; ``fake``, ``vault-kv`` (D0),
  ``vault-k8s-token`` (D1), ``remote-mint`` (not implemented: acb-ops, P2).
- ``registry`` — checkouts: values in memory, value-free state file, reaper.
- ``harness`` — advisory harness attribution from the peer's process tree.
- ``service`` — request handling, independent of sockets.
- ``server`` — the AF_UNIX server and the ``acb-broker`` entry point (Linux).
- ``client`` — socket client and the functions ``acb checkouts`` / ``acb
  revoke`` will wire (``list_checkouts``, ``revoke_checkouts``).
- ``git_credential`` / ``kube_credential`` — helper front-ends.

Importing this package imports nothing outside the standard library and acb's
own stdlib-only core; ``hvac`` is reached lazily through ``cred_vault`` only
when a Vault issuer runs.
"""
