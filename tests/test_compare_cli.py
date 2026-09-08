"""The comparison CLI, and the selection logic that keeps it honest.

`dnsguard/diff.py` computes the comparison and is tested there. What is tested
here is everything around it — which of many previous reports to compare
against, and what happens when the answer is "none of them".

That selection is the part with teeth. The scan workflow assesses whatever domain
it is asked to, so the run before this one is frequently a different client's
domain, and comparing across targets produces a diff where everything is new and
everything is resolved: true, and useless, and alarming.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "compare.py"


def report(
    scan_id="scan-2",
    domain="acme.example",
    at="2026-09-08T00:00:00Z",
    findings=(),
):
    return {
        "schema": "icit.dnsguard.report.v2",
        "scan_id": scan_id,
        "domain": domain,
        "target": domain,
        "scan_timestamp": at,
        "findings": list(findings),
    }


def finding(title="Missing SPF Record", severity="high", asset="acme.example"):
    return {
        "module": "spf_audit",
        "target": "acme.example",
        "asset": asset,
        "title": title,
        "severity": severity,
        "fingerprint": f"fp-{title}-{asset}",
    }


def write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args], capture_output=True, text=True, cwd=str(ROOT)
    )


# ── comparing two reports ────────────────────────────────────────────────────


def test_a_worsening_is_reported(tmp_path):
    old = write(
        tmp_path / "old.json",
        report("s-1", at="2026-09-01T00:00:00Z", findings=[finding(severity="low")]),
    )
    new = write(tmp_path / "new.json", report("s-2", findings=[finding(severity="critical")]))
    result = run("--current", str(new), "--previous", str(old))
    assert result.returncode == 0
    assert "SOMETHING GOT WORSE" in result.stdout
    assert "worsened" in result.stdout


def test_nothing_moving_says_so(tmp_path):
    old = write(
        tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[finding()])
    )
    new = write(tmp_path / "new.json", report("s-2", findings=[finding()]))
    result = run("--current", str(new), "--previous", str(old))
    assert "nothing got worse" in result.stdout


def test_an_unchanged_severity_is_not_annotated(tmp_path):
    """A resolved finding carries its own severity as its previous one, so
    "(was info)" beside "info" is noise dressed as detail."""
    old = write(
        tmp_path / "old.json",
        report("s-1", at="2026-09-01T00:00:00Z", findings=[finding(severity="info")]),
    )
    new = write(tmp_path / "new.json", report("s-2", findings=[]))
    result = run("--current", str(new), "--previous", str(old))
    assert "resolved" in result.stdout
    assert "(was info)" not in result.stdout


# ── a regression must not fail the pipeline ──────────────────────────────────


def test_a_regression_exits_zero_by_default(tmp_path):
    """This runs inside the pipeline that serves the public free scan. A red run
    reads as "the scan broke", which is the opposite of "your DNS got worse"."""
    old = write(tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[]))
    new = write(tmp_path / "new.json", report("s-2", findings=[finding(severity="critical")]))
    assert run("--current", str(new), "--previous", str(old)).returncode == 0


def test_failing_on_a_regression_can_be_asked_for(tmp_path):
    old = write(tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[]))
    new = write(tmp_path / "new.json", report("s-2", findings=[finding(severity="critical")]))
    result = run("--current", str(new), "--previous", str(old), "--fail-on-regression")
    assert result.returncode == 1


def test_asking_to_fail_does_not_fail_when_nothing_got_worse(tmp_path):
    old = write(
        tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[finding()])
    )
    new = write(tmp_path / "new.json", report("s-2", findings=[finding()]))
    assert (
        run("--current", str(new), "--previous", str(old), "--fail-on-regression").returncode == 0
    )


# ── selecting from candidates: the part with teeth ───────────────────────────


def test_the_newest_report_for_the_same_target_is_chosen(tmp_path):
    candidates = tmp_path / "runs"
    candidates.mkdir()
    write(candidates / "a.json", report("old", at="2026-09-01T00:00:00Z", findings=[finding()]))
    write(candidates / "b.json", report("newer", at="2026-09-05T00:00:00Z", findings=[finding()]))
    new = write(
        tmp_path / "new.json",
        report("s-3", at="2026-09-08T00:00:00Z", findings=[finding(severity="critical")]),
    )

    result = run("--current", str(new), "--candidates", str(candidates))
    assert "since newer" in result.stdout


def test_a_report_for_another_domain_is_not_used(tmp_path):
    """The failure this guards: everything new and everything resolved, on a
    domain that never changed."""
    candidates = tmp_path / "runs"
    candidates.mkdir()
    write(
        candidates / "other.json",
        report(
            "other",
            domain="globex.example",
            at="2026-09-05T00:00:00Z",
            findings=[finding(title="Something else")],
        ),
    )
    new = write(
        tmp_path / "new.json", report("s-3", at="2026-09-08T00:00:00Z", findings=[finding()])
    )

    result = run("--current", str(new), "--candidates", str(candidates))
    assert "baseline" in result.stdout
    assert "none of them for acme.example" in result.stdout


def test_a_later_report_is_not_treated_as_previous(tmp_path):
    """Artifacts arrive in whatever order they download. "Previous" means
    earlier, not "some other file"."""
    candidates = tmp_path / "runs"
    candidates.mkdir()
    write(
        candidates / "later.json", report("later", at="2026-09-09T00:00:00Z", findings=[finding()])
    )
    new = write(
        tmp_path / "new.json", report("s-3", at="2026-09-08T00:00:00Z", findings=[finding()])
    )
    assert "baseline" in run("--current", str(new), "--candidates", str(candidates)).stdout


def test_the_current_report_is_not_compared_against_itself(tmp_path):
    candidates = tmp_path / "runs"
    candidates.mkdir()
    same = report("s-3", at="2026-09-08T00:00:00Z", findings=[finding()])
    write(candidates / "self.json", same)
    new = write(tmp_path / "new.json", same)
    assert "baseline" in run("--current", str(new), "--candidates", str(candidates)).stdout


def test_an_empty_candidate_directory_is_a_baseline(tmp_path):
    candidates = tmp_path / "runs"
    candidates.mkdir()
    new = write(tmp_path / "new.json", report("s-1", findings=[finding()]))
    result = run("--current", str(new), "--candidates", str(candidates))
    assert result.returncode == 0
    assert "no earlier report was available" in result.stdout


def test_junk_among_the_candidates_is_skipped_not_fatal(tmp_path):
    """Downloaded artifacts include whatever else was in them. One unreadable
    file must not stop the comparison."""
    candidates = tmp_path / "runs"
    candidates.mkdir()
    (candidates / "broken.json").write_text("{not json", encoding="utf-8")
    (candidates / "unrelated.json").write_text('{"hello": "world"}', encoding="utf-8")
    write(candidates / "good.json", report("prev", at="2026-09-01T00:00:00Z", findings=[finding()]))
    new = write(tmp_path / "new.json", report("s-2", findings=[finding()]))

    result = run("--current", str(new), "--candidates", str(candidates))
    assert result.returncode == 0
    assert "since prev" in result.stdout


def test_candidates_are_found_in_nested_directories(tmp_path):
    """`gh run download` puts each run in its own directory."""
    candidates = tmp_path / "runs"
    (candidates / "1234" / "dnsguard-report-x").mkdir(parents=True)
    write(
        candidates / "1234" / "dnsguard-report-x" / "r.json",
        report("prev", at="2026-09-01T00:00:00Z", findings=[finding()]),
    )
    new = write(tmp_path / "new.json", report("s-2", findings=[finding()]))
    assert "since prev" in run("--current", str(new), "--candidates", str(candidates)).stdout


# ── an explicit mismatch is refused rather than silently wrong ───────────────


def test_comparing_two_different_domains_explicitly_is_refused(tmp_path):
    old = write(tmp_path / "old.json", report("s-1", domain="globex.example"))
    new = write(tmp_path / "new.json", report("s-2", domain="acme.example"))
    result = run("--current", str(new), "--previous", str(old))
    assert result.returncode == 2
    assert "refusing to compare" in result.stderr


# ── output shapes ────────────────────────────────────────────────────────────


def test_the_markdown_summary_leads_with_the_answer(tmp_path):
    old = write(tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[]))
    new = write(tmp_path / "new.json", report("s-2", findings=[finding(severity="critical")]))
    out = run("--current", str(new), "--previous", str(old), "--summary-md").stdout
    assert out.splitlines()[0].startswith("### DNS Guard")
    assert "Something got worse" in out
    assert "| Change | Severity | Affected | Finding |" in out


def test_the_json_output_is_machine_readable(tmp_path):
    old = write(tmp_path / "old.json", report("s-1", at="2026-09-01T00:00:00Z", findings=[]))
    new = write(tmp_path / "new.json", report("s-2", findings=[finding()]))
    payload = json.loads(run("--current", str(new), "--previous", str(old), "--json").stdout)
    assert payload["regressed"] is True
    assert payload["summary"]["new"] == 1


def test_the_json_output_says_why_there_was_no_previous(tmp_path):
    candidates = tmp_path / "runs"
    candidates.mkdir()
    new = write(tmp_path / "new.json", report("s-1", findings=[finding()]))
    payload = json.loads(
        run("--current", str(new), "--candidates", str(candidates), "--json").stdout
    )
    assert payload["baseline"] is True
    assert "no earlier report" in payload["no_previous_because"]


# ── usage errors ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "args",
    [
        ("--current", "/nonexistent.json", "--previous", "/also-missing.json"),
        ("--current", "/nonexistent.json", "--candidates", "/nowhere"),
    ],
)
def test_a_missing_file_is_a_usage_error(args):
    assert run(*args).returncode == 2


def test_a_missing_candidates_directory_is_a_usage_error(tmp_path):
    new = write(tmp_path / "new.json", report())
    assert run("--current", str(new), "--candidates", str(tmp_path / "nope")).returncode == 2
