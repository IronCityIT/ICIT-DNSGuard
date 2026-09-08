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


# ── the client page shows what the report actually carries ───────────────────


def test_the_findings_table_has_an_affected_column(index):
    """Several findings all reading as the scanned domain is not something a
    reader can act on. The specific host is the first thing they need."""
    head = re.search(r"<thead><tr>(.*?)</tr></thead>", index, re.S)
    assert head, "the findings table lost its header"
    assert "Affected" in head.group(1)


def test_the_placeholder_rows_match_the_column_count(index):
    """The static rows are what a visitor sees before the fetch resolves. A row
    narrower than the header renders as a broken table."""
    head = re.search(r"<thead><tr>(.*?)</tr></thead>", index, re.S).group(1)
    columns = len(re.findall(r"<th>", head))
    body = re.search(r'<tbody id="findings-body">(.*?)</tbody>', index, re.S).group(1)
    for row in re.findall(r"<tr>(.*?)</tr>", body, re.S):
        assert len(re.findall(r"<td>", row)) == columns


def test_an_unconfirmed_finding_is_labelled_as_such(index):
    """A check that could not complete must not render like one that proved
    something. This is the same distinction the report contract carries, one
    layer up — and the layer the client actually reads."""
    js = inline_js(INDEX)
    assert "confidence" in js
    assert "confidence-tag" in js
    assert "!== 'confirmed'" in js or '!== "confirmed"' in js


def test_the_confidence_tag_has_a_visible_style(index):
    assert ".confidence-tag" in index


def test_the_affected_host_and_confidence_are_set_as_text_not_markup(index):
    """Both new values come from a Firestore document. They must be built the
    same way every other value on this page is — as text — or the stored-XSS fix
    is undone by the columns added after it."""
    js = inline_js(INDEX)
    for line in js.splitlines():
        if "confidence-tag" in line or "affected-host" in line:
            assert ".innerHTML" not in line, line
    assert "tag.textContent" in js


def test_every_severity_the_report_can_emit_has_a_pill_style(index):
    """A severity with no style renders as unstyled text next to styled peers,
    which reads as a rendering fault rather than as a finding."""
    for severity in ("critical", "high", "medium", "low", "info"):
        assert f".severity-pill.{severity}" in index, severity


# ── the scans panel ──────────────────────────────────────────────────────────


def test_the_console_has_a_scans_tab(console_js):
    """The scan store, change detection and shareable links had no operator
    surface at all until this panel existed."""
    html = CONSOLE_HTML.read_text(encoding="utf-8")
    assert 'data-tab="scans"' in html
    assert 'data-panel="scans"' in html
    assert 'id="scans-body"' in html
    assert "scans: renderScans" in console_js


def test_every_tab_has_a_panel_and_a_renderer(console_js):
    """A tab with no panel renders nothing and looks broken; a panel with no
    renderer throws. Adding one and forgetting the others is the easy mistake."""
    html = CONSOLE_HTML.read_text(encoding="utf-8")
    tabs = set(re.findall(r'data-tab="([a-z]+)"', html))
    panels = set(re.findall(r'data-panel="([a-z]+)"', html))
    renderers = set(re.findall(r"^\s+([a-z]+): render[A-Z]", console_js, re.M))
    assert tabs == panels, f"tabs and panels disagree: {tabs ^ panels}"
    assert tabs <= renderers, f"tabs with no renderer: {tabs - renderers}"


def test_a_baseline_is_not_presented_as_a_page_of_new_problems(console_js):
    """`diff.py` is careful that a first scan is a baseline rather than "N things
    just broke". Labelling every row "new" underneath that banner reintroduces
    the same confusion one layer up."""
    assert 'data.baseline ? "found" : change.outcome' in console_js
    assert 'data.baseline ? "State" : "Change"' in console_js


def test_the_headline_is_whether_anything_got_worse(console_js):
    """A count of changes answers a different question, and reads as alarming
    when most of them are improvements."""
    assert "data.regressed" in console_js
    assert "Nothing got worse since the previous assessment." in console_js


def test_both_severities_are_shown_when_one_became_the_other(console_js):
    """ "medium to critical" is the fact. Either number alone is half of it."""
    assert "change.previous_severity" in console_js
    assert 'text: " was " + change.previous_severity' in console_js


def test_an_unproven_change_is_labelled(console_js):
    assert 'change.confidence !== "confirmed"' in console_js


def test_minting_a_share_link_asks_first(console_js):
    """It grants access to somebody without an account. The operator should be
    asked before that happens, not told afterwards."""
    minting = console_js[console_js.index("function mintLink") :]
    assert "window.confirm" in minting.split("function ")[1]
    assert "without signing in" in console_js


def test_the_scans_panel_builds_no_markup_from_stored_data(console_js):
    """Scan documents are written by the pipeline and rendered here. The console
    has never used innerHTML and adding a panel is exactly when that slips."""
    panel = console_js[console_js.index("function renderScans") : console_js.index("var RENDERERS")]
    assert ".innerHTML" not in panel
    assert "insertAdjacentHTML" not in panel
