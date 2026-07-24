"""e2e exec: broker a provisioned browser into a child, honestly (WI-A).

Hermetic by construction — the "browser layer" is a fake executable placed in a
fake Playwright cache, so these tests never launch a real browser (the real one
is exercised by `scripts/e2e_live_proof.py`, see docs/e2e-live-proof.md). What
is asserted here is the contract: the child receives the concrete brokered
browser and nothing else has to be discovered by it; the exit code is the
child's; and an unprovisioned capability fails with the contract-v1 error
envelope instead of a crash — with no child launched.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import E2eProvider, E2eUnavailable, _resolve_local_browser

CAP = Capability(
    "e2e:chromium", "e2e", ("opencode",),
    {"engine": "playwright", "browser": "chromium", "backend": "local"},
)
MARKER = "ACB-FAKE-DOM-MARKER"

_FAKE_BROWSER = f"""\
#!{sys.executable}
# A fake browser: honors --dump-dom by printing a DOM containing the marker.
import sys
if "--dump-dom" in sys.argv:
    print("<html><body><h1>{MARKER}</h1></body></html>")
    raise SystemExit(0)
raise SystemExit(1)
"""


def _cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *builds: str) -> Path:
    """A fake Playwright browser cache with an executable fake browser per build."""
    cache = tmp_path / "ms-playwright"
    for build in builds:
        exe = cache / build / "chrome-linux64" / "chrome"
        exe.parent.mkdir(parents=True)
        exe.write_text(_FAKE_BROWSER, encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return cache


def _reporter(out: Path) -> list[str]:
    """A child that records the e2e environment it was handed."""
    code = (
        "import json, os, pathlib; "
        f"pathlib.Path(r'{out}').write_text(json.dumps("
        "{k: v for k, v in os.environ.items() if k.startswith(('ACB_E2E', 'PLAYWRIGHT'))}))"
    )
    return [sys.executable, "-c", code]


# --- resolution --------------------------------------------------------------


def test_resolves_newest_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1100", "chromium-1228", "chromium-999")
    exe, _ = _resolve_local_browser("chromium")
    assert exe.parts[-3] == "chromium-1228"


def test_chromium_falls_back_to_headless_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "ms-playwright"
    exe = cache / "chromium_headless_shell-1228" / "chrome-headless-shell-linux64"
    exe.mkdir(parents=True)
    (exe / "chrome-headless-shell").write_text("x", encoding="utf-8")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))
    resolved, _ = _resolve_local_browser("chromium")
    assert resolved.name == "chrome-headless-shell"


def test_unknown_browser_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    with pytest.raises(E2eUnavailable, match="unsupported browser"):
        _resolve_local_browser("lynx")


# --- exec: the brokered child ------------------------------------------------


def test_child_receives_the_brokered_browser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = _cache(tmp_path, monkeypatch, "chromium-1228")
    out = tmp_path / "seen.json"

    rc = E2eProvider().exec(CAP, _reporter(out))

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["ACB_E2E_BACKEND"] == "local"
    assert seen["ACB_E2E_BROWSER"] == "chromium"
    assert seen["ACB_E2E_CAPABILITY"] == "e2e:chromium"
    assert seen["PLAYWRIGHT_BROWSERS_PATH"] == str(cache)
    assert Path(seen["ACB_E2E_EXECUTABLE"]).is_file()


@pytest.mark.skipif(
    os.name == "nt", reason="the fake browser is a POSIX shebang script"
)
def test_child_can_drive_the_brokered_browser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The composition the live proof runs, with the browser layer faked.

    The real proof task (`scripts/e2e_browser_task.py`) is the child; it knows
    nothing but the injected env, launches whatever `ACB_E2E_EXECUTABLE` points
    at, and asserts the rendered DOM.
    """
    _cache(tmp_path, monkeypatch, "chromium-1228")
    task = Path(__file__).resolve().parents[1] / "scripts" / "e2e_browser_task.py"

    rc = E2eProvider().exec(
        CAP,
        [sys.executable, str(task), "--url", "http://127.0.0.1/never-fetched",
         "--expect", MARKER],
    )

    assert rc == 0


def test_child_exit_code_is_propagated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    rc = E2eProvider().exec(CAP, [sys.executable, "-c", "raise SystemExit(7)"])
    assert rc == 7


def test_provenance_records_the_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    E2eProvider().exec(CAP, [sys.executable, "-c", ""])
    events = [
        json.loads(line)
        for line in (tmp_path / "state" / "provenance.jsonl").read_text().splitlines()
    ]
    assert [e["result"] for e in events] == ["started", "applied"]
    assert all(e["capability"] == "e2e:chromium" for e in events)


def test_empty_argv_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    with pytest.raises(ValueError, match="requires a command"):
        E2eProvider().exec(CAP, [])


# --- exec: the honest negative paths ----------------------------------------


def test_no_browsers_fails_without_launching_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    sentinel = tmp_path / "child-ran"

    with pytest.raises(E2eUnavailable, match="playwright install"):
        E2eProvider().exec(
            CAP,
            [sys.executable, "-c", f"open(r'{sentinel}', 'w').close()"],
        )

    assert not sentinel.exists()               # nothing was launched
    assert not (tmp_path / "state").exists()   # and nothing claimed an execution


def test_unknown_backend_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    cap = Capability("e2e:chromium", "e2e", ("opencode",), {"backend": "carrier-pigeon"})
    with pytest.raises(E2eUnavailable, match="unknown backend"):
        E2eProvider().exec(cap, [sys.executable, "-c", ""])


def test_unknown_engine_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    cap = Capability("e2e:chromium", "e2e", ("opencode",), {"engine": "selenium"})
    with pytest.raises(E2eUnavailable, match="unsupported engine"):
        E2eProvider().exec(cap, [sys.executable, "-c", ""])


def test_remote_backend_brokers_the_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    out = tmp_path / "seen.json"
    cap = Capability(
        "e2e:remote", "e2e", ("opencode",),
        {"backend": "remote", "endpoint": "ws://browser.example.invalid:3000/"},
    )

    rc = E2eProvider().exec(cap, _reporter(out))

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["ACB_E2E_BACKEND"] == "remote"
    assert seen["ACB_E2E_ENDPOINT"] == "ws://browser.example.invalid:3000/"
    assert "ACB_E2E_EXECUTABLE" not in seen


def test_remote_backend_without_endpoint_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    cap = Capability("e2e:remote", "e2e", ("opencode",), {"backend": "remote"})
    with pytest.raises(E2eUnavailable, match="requires options.endpoint"):
        E2eProvider().exec(cap, [sys.executable, "-c", ""])


# --- CLI surface: contract-v1 envelope, unchanged exit taxonomy --------------


def _manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."e2e:chromium"]\nprovider = "e2e"\nbrowser = "chromium"\n'
        'backend = "local"\nharnesses = ["opencode"]\n',
        encoding="utf-8",
    )
    return m


def test_cli_unprovisioned_emits_error_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    rc = main([
        "exec", "-m", str(_manifest(tmp_path)), "--json", "e2e:chromium", "--",
        sys.executable, "-c", "",
    ])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "E2E_UNAVAILABLE"
    assert "Traceback" not in captured.err
    # The exec exit taxonomy is load-bearing for the live cred-* skills: 2, as before.
    assert rc == 2


def test_cli_unprovisioned_human_mode_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    rc = main([
        "exec", "-m", str(_manifest(tmp_path)), "e2e:chromium", "--", sys.executable, "-c", "",
    ])

    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""                       # no JSON on the child's stream
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err


def test_cli_exec_runs_the_brokered_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _cache(tmp_path, monkeypatch, "chromium-1228")
    out = tmp_path / "seen.json"
    rc = main(["exec", "-m", str(_manifest(tmp_path)), "e2e:chromium", "--", *_reporter(out)])
    assert rc == 0
    assert json.loads(out.read_text())["ACB_E2E_BACKEND"] == "local"


def test_json_after_the_separator_belongs_to_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--json` is a head-only flag: after `--` it is the child's argument."""
    _cache(tmp_path, monkeypatch, "chromium-1228")
    out = tmp_path / "argv.json"
    code = f"import json,sys,pathlib; pathlib.Path(r'{out}').write_text(json.dumps(sys.argv[1:]))"
    rc = main([
        "exec", "-m", str(_manifest(tmp_path)), "e2e:chromium", "--",
        sys.executable, "-c", code, "--json",
    ])
    assert rc == 0
    assert json.loads(out.read_text()) == ["--json"]


def test_exec_does_not_inherit_a_stale_e2e_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pre-set ACB_E2E_* in the parent must not survive as the brokered value."""
    _cache(tmp_path, monkeypatch, "chromium-1228")
    monkeypatch.setenv("ACB_E2E_EXECUTABLE", "/usr/bin/not-the-brokered-browser")
    monkeypatch.setenv("ACB_E2E_BACKEND", "remote")
    out = tmp_path / "seen.json"

    E2eProvider().exec(CAP, _reporter(out))

    seen = json.loads(out.read_text())
    assert seen["ACB_E2E_BACKEND"] == "local"
    assert seen["ACB_E2E_EXECUTABLE"] != "/usr/bin/not-the-brokered-browser"
    assert os.environ["ACB_E2E_EXECUTABLE"] == "/usr/bin/not-the-brokered-browser"
