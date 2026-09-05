"""Static assertions about the two shipped pages.

There is no build step for dashboard/public — the files are served as-is — so
these are the only checks between an edit and a client's browser. They test
properties that would be expensive to notice any other way: XSS-shaped
interpolation, tool names leaking to a client surface, and the console needing
'unsafe-inline' that its CSP does not grant.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "dashboard" / "public"
INDEX = PUBLIC / "index.html"
CONSOLE_HTML = PUBLIC / "console.html"
CONSOLE_JS = PUBLIC / "console.js"


@pytest.fixture(scope="module")
def index() -> str:
    return INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def console_js() -> str:
    return CONSOLE_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def firebase() -> dict:
    return json.loads((ROOT / "firebase.json").read_text(encoding="utf-8"))


def inline_js(path: Path) -> str:
    proc = subprocess.run(
        ["python3", "tools/extract_inline_js.py", str(path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


# ── XSS surface ──────────────────────────────────────────────────────────────

# innerHTML assigned anything that is not a constant: a template literal, a
# concatenation, a variable, or a .map(). A fixed string is harmless.
DYNAMIC_INNERHTML = re.compile(r"\.innerHTML\s*=\s*(?P<value>.*)$")
CONSTANT = re.compile(r"^'[^'`$]*'\s*;\s*$|^\"[^\"`$]*\"\s*;\s*$")


def test_no_stored_scan_data_is_interpolated_into_markup(index):
    """A scan document is not ours to trust: it is stored in Firestore, reachable
    by a ?scan=<id> link, and its fields end up on the page. Interpolating any of
    it into innerHTML is a stored-XSS delivery path."""
    offenders = []
    for line in index.splitlines():
        match = DYNAMIC_INNERHTML.search(line)
        if match and not CONSTANT.match(match.group("value").strip()):
            offenders.append(line.strip())
    assert offenders == [], f"dynamic innerHTML assignment: {offenders}"


def test_the_console_never_uses_innerhtml_at_all(console_js):
    assert ".innerHTML" not in console_js
    assert "insertAdjacentHTML" not in console_js
    assert "document.write" not in console_js


def test_neither_page_evaluates_strings_as_code(index, console_js):
    for source, name in ((index, "index.html"), (console_js, "console.js")):
        assert not re.search(r"\beval\s*\(", source), name
        assert not re.search(r"new\s+Function\s*\(", source), name


# ── Firestore access shape ───────────────────────────────────────────────────


def test_the_dashboard_reads_documents_by_id_and_never_queries(index):
    """`list` is denied by the security rules so nobody can enumerate every scan.
    A collection query would therefore return nothing — and the page must not
    depend on one."""
    assert ".where(" not in index, "a collection query needs list permission, which the rules deny"
    assert "collection('scans').doc(" in index


def test_the_dashboard_does_not_write_to_firestore(index):
    for method in (".set(", ".add(", ".update(", ".delete("):
        assert "collection('scans')" + method not in index


# ── security rules ───────────────────────────────────────────────────────────


def test_rules_deny_all_client_writes():
    rules = (ROOT / "firestore.rules").read_text(encoding="utf-8")
    assert "allow create, update, delete: if false;" in rules
    assert "allow read, write: if false;" in rules, "unlisted collections must be denied"


def test_rules_permit_get_but_not_list():
    """In Firestore `read` grants get AND list. Splitting them is the whole point
    — it is what stops bulk harvesting of every scan and submitter email."""
    rules = (ROOT / "firestore.rules").read_text(encoding="utf-8")
    assert "allow get: if true;" in rules
    assert "allow list: if false;" in rules
    assert not re.search(r"allow read\s*:\s*if true", rules)


# ── hosting headers ──────────────────────────────────────────────────────────


def test_the_rules_file_is_actually_wired_into_the_deployment(firebase):
    """A rules file that firebase.json does not reference is never deployed —
    which is exactly why this project ran on test-mode rules for so long."""
    assert firebase["firestore"]["rules"] == "firestore.rules"
    assert (ROOT / "firestore.rules").is_file()


def test_baseline_security_headers_apply_to_every_path(firebase):
    baseline = next(h for h in firebase["hosting"]["headers"] if h["source"] == "**")
    keys = {header["key"] for header in baseline["headers"]}
    assert {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
    } <= keys


def csp_for(firebase: dict, source: str) -> str:
    entry = next(h for h in firebase["hosting"]["headers"] if h["source"] == source)
    return next(h["value"] for h in entry["headers"] if h["key"] == "Content-Security-Policy")


def test_the_console_csp_forbids_inline_script(firebase):
    csp = csp_for(firebase, "/console.html")
    script_src = next(part for part in csp.split(";") if part.strip().startswith("script-src"))
    assert "unsafe-inline" not in script_src
    assert "unsafe-eval" not in csp
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_the_console_page_has_nothing_inline_for_that_csp_to_break():
    """The strict policy above is only honest if the page actually complies."""
    html = CONSOLE_HTML.read_text(encoding="utf-8")
    assert inline_js(CONSOLE_HTML).strip() == "", "console.html must have no inline script"
    assert "<style" not in html, "console.html must have no inline <style>"
    assert not re.search(r"\son[a-z]+\s*=", html), "console.html must have no inline event handlers"


def resource_origins(html: str) -> set[str]:
    """Origins the page actually LOADS from.

    Deliberately not every https:// in the file: an <a href> is a navigation,
    which no directive in this policy governs, and counting it would push a link
    target into connect-src for no reason.
    """
    origins = set()
    for url in re.findall(r'\bsrc\s*=\s*"(https://[^"]+)"', html):
        origins.add("https://" + url.split("//", 1)[1].split("/", 1)[0])
    for tag in re.findall(r"<link\b[^>]*>", html, flags=re.IGNORECASE):
        for url in re.findall(r'href\s*=\s*"(https://[^"]+)"', tag):
            origins.add("https://" + url.split("//", 1)[1].split("/", 1)[0])
    script = re.search(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.DOTALL)
    if script:
        for url in re.findall(r"https://[a-z0-9.\-]+", script.group(1)):
            origins.add(url)
    return origins


def test_the_free_scan_csp_covers_every_origin_the_page_loads(index, firebase):
    """A CSP that omits an origin the page needs breaks the page silently — the
    browser blocks the request and logs to a console nobody is watching."""
    csp = csp_for(firebase, "/index.html")
    wildcards = re.findall(r"https://\*\.([a-z0-9.\-]+)", csp)
    for origin in sorted(resource_origins(index)):
        host = origin.split("//", 1)[1]
        covered = origin in csp or any(suffix and host.endswith(suffix) for suffix in wildcards)
        assert covered, f"{origin} is loaded by the page but absent from its CSP"


def test_the_page_loads_its_own_brand_mark_not_a_third_party_copy(index):
    """The logo used to be pulled from raw.githubusercontent.com, which put a
    third party in the load path of a client-facing page and handed them every
    visitor's IP address. The file is in this directory."""
    assert "raw.githubusercontent.com" not in index
    assert 'src="/logo.png"' in index


# ── white-label ──────────────────────────────────────────────────────────────


def test_no_underlying_tool_is_named_on_a_client_facing_page(index):
    banned = (
        "nuclei",
        "zap",
        "wazuh",
        "prowler",
        "puppeteer",
        "checkdmarc",
        "dnsperf",
        "crt.sh",
        "traceroute",
        "tools_used",
        "bruteforce",
    )
    lowered = index.lower()
    for term in banned:
        assert term not in lowered, term


def test_the_console_names_no_tooling_either(console_js):
    html = CONSOLE_HTML.read_text(encoding="utf-8").lower()
    for term in ("nuclei", "zap", "wazuh", "prowler", "checkdmarc", "dnsperf", "crt.sh"):
        assert term not in html and term not in console_js.lower(), term


# ── console resilience ───────────────────────────────────────────────────────


def test_the_console_never_retries_a_non_idempotent_request(console_js):
    """Re-sending a POST could publish a policy or grant an exception twice."""
    assert 'method === "GET" ? RETRIES : 1' in console_js


def test_the_console_bounds_every_request_with_a_timeout(console_js):
    assert "AbortController" in console_js
    assert "TIMEOUT_MS" in console_js


def test_the_console_treats_202_as_pending_approval_not_failure(console_js):
    assert "err.status === 202" in console_js
    assert "approval_request_id" in console_js


def test_the_console_confirms_before_changing_enforcement(console_js):
    assert "window.confirm" in console_js
    assert "Protection is removed" in console_js


def test_the_console_handles_going_offline(console_js):
    assert '"offline"' in console_js
    assert '"online"' in console_js


def test_browser_storage_access_is_guarded(console_js):
    """localStorage throws outright in browsers configured to block site data."""
    for block in re.findall(r"localStorage[\s\S]{0,200}", console_js):
        assert "try" in console_js[: console_js.index(block) + len(block)]
