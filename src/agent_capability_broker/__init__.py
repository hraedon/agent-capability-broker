"""agent-capability-broker: keep agents at capability parity across harnesses.

The deterministic core (model, manifest parsing, the read-only inspect/doctor
path) is stdlib-only. Provider backends (Vault for `cred`) and any narration
layer are optional extras that the core never imports.
"""

__version__ = "0.1.0"
