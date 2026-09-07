"""The web security policy, kept portable so the migration cannot delete it.

HSTS, a strict CSP with no `unsafe-inline` on the console, `frame-ancestors
'none'` and an exact `connect-src` list were all built deliberately, and all of
them currently live inside `firebase.json`. Firebase Hosting is retired from the
target architecture, so without a home of their own that hardening would be
deleted along with the platform and rediscovered later, one incident at a time.

`deploy/web-headers.json` is now the source of truth. `firebase.json` still
carries the same policy while Firebase Hosting is still what serves the site, and
the parity test below is what stops the two drifting while both exist.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "deploy" / "web-headers.json"
FIREBASE = ROOT / "firebase.json"
RENDER = ROOT / "tools" / "render-headers.py"


@pytest.fixture(scope="module")
def policy() -> list[dict]:
    return json.loads(POLICY.read_text(encoding="utf-8"))["paths"]


def render(server: str) -> str:
    result = subprocess.run(
        ["python3", str(RENDER), "--server", server],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=True,
    )
    return result.stdout


def headers_for(policy: list[dict], path: str) -> dict[str, str]:
    return next(entry["headers"] for entry in policy if entry["path"] == path)


# ── parity: the whole point of the file ──────────────────────────────────────


def test_the_policy_and_firebase_still_agree():
    """While both exist, they must say the same thing. A policy that has quietly
    diverged from what is actually served is worse than no policy file, because
    it reads as evidence."""
    result = subprocess.run(
        ["python3", str(RENDER), "--check", str(FIREBASE)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode == 0, result.stderr


def test_the_parity_check_actually_fails_on_a_difference(tmp_path):
    """A check that cannot fail is not a check. This proves it would notice."""
    firebase = json.loads(FIREBASE.read_text(encoding="utf-8"))
    firebase["hosting"]["headers"][0]["headers"][0]["value"] = "something-else"
    altered = tmp_path / "firebase.json"
    altered.write_text(json.dumps(firebase), encoding="utf-8")

    result = subprocess.run(
        ["python3", str(RENDER), "--check", str(altered)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode != 0
    assert "differs" in result.stderr


def test_the_parity_check_notices_a_header_being_dropped(tmp_path):
    """The likelier accident: somebody removes a header rather than changing
    one, and nothing complains because what is left still matches."""
    firebase = json.loads(FIREBASE.read_text(encoding="utf-8"))
    firebase["hosting"]["headers"][0]["headers"].pop()
    altered = tmp_path / "firebase.json"
    altered.write_text(json.dumps(firebase), encoding="utf-8")

    result = subprocess.run(
        ["python3", str(RENDER), "--check", str(altered)],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert result.returncode != 0
    assert "not firebase.json" in result.stderr


# ── the policy still says the things that matter ─────────────────────────────


def test_the_baseline_applies_to_every_path(policy):
    keys = set(headers_for(policy, "**"))
    assert {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "Permissions-Policy",
    } <= keys


def test_the_console_policy_permits_no_inline_script(policy):
    csp = headers_for(policy, "/console.html")["Content-Security-Policy"]
    script_src = next(part for part in csp.split(";") if part.strip().startswith("script-src"))
    assert "unsafe-inline" not in script_src
    assert "unsafe-eval" not in csp


@pytest.mark.parametrize("path", ["/index.html", "/console.html"])
def test_neither_page_may_be_framed(policy, path):
    csp = headers_for(policy, path)["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    assert "object-src 'none'" in csp


def test_hsts_is_at_least_a_year(policy):
    hsts = headers_for(policy, "**")["Strict-Transport-Security"]
    max_age = int(hsts.split("max-age=")[1].split(";")[0])
    assert max_age >= 31536000


# ── the rendered output carries everything ───────────────────────────────────


@pytest.mark.parametrize("server", ["caddy", "nginx"])
def test_every_header_survives_rendering(policy, server):
    """A renderer that silently drops a header would hand somebody a config that
    looks complete and serves a weaker site than the policy describes."""
    rendered = render(server)
    for entry in policy:
        for key, value in entry["headers"].items():
            assert key in rendered, f"{server} output is missing {key}"
            assert value in rendered, f"{server} output is missing the value of {key}"


def test_nginx_marks_every_header_always():
    """Without `always`, nginx omits the header on error responses — so a 404 or
    a 502 would be served with no CSP, and an error page is exactly where
    injected content tends to end up."""
    rendered = render("nginx")
    directives = [
        line
        for line in rendered.splitlines()
        if "add_header" in line and not line.lstrip().startswith("#")
    ]
    assert directives
    for line in directives:
        assert line.rstrip().endswith("always;"), line


def test_nginx_repeats_the_baseline_inside_each_location(policy):
    """nginx does not inherit add_header into a location that sets its own. A
    location block carrying only its CSP would silently lose HSTS and the rest."""
    rendered = render("nginx")
    blocks = rendered.split("location = ")[1:]
    assert blocks, "no location blocks were rendered"
    for block in blocks:
        for key in headers_for(policy, "**"):
            assert key in block, f"a location block is missing the baseline header {key}"


def test_the_rendered_config_says_where_it_came_from():
    """Somebody will find this on a server in a year and need to know not to
    edit it in place."""
    for server in ("caddy", "nginx"):
        assert "deploy/web-headers.json" in render(server)


# ── the file explains itself ─────────────────────────────────────────────────


def test_the_policy_records_why_each_exception_exists():
    """The free-scan page's `unsafe-inline` is a real weakening. It is carried
    with the note explaining it rather than as a bare setting somebody later
    copies onto a page that does not need it."""
    entries = json.loads(POLICY.read_text(encoding="utf-8"))["paths"]
    index = next(e for e in entries if e["path"] == "/index.html")
    assert index["note"], "the page with unsafe-inline must say why"
    assert "inline" in index["note"].lower()
