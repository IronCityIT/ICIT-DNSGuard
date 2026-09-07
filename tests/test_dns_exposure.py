"""The DNS exposure ratchet: does it hold the line, and does it stay honest?

Two failure modes are worth more than all the others here, and both are about
the gate lying in the reassuring direction:

  * a posture that got worse being read as unchanged, so the build stays green
    while the exposure grows;
  * a check that could not measure anything being reported as a pass.

Everything else is bookkeeping.
"""

from __future__ import annotations

import json
import pathlib

from dnsguard.dns_exposure import MEANINGS, POSTURES, compare, rank, summarise

BASELINE = pathlib.Path(__file__).resolve().parent.parent / "dns-baseline.json"


def row(host, verdict, destination="gone.example.net", **extra):
    return {"host": host, "destination": destination, "verdict": verdict, **extra}


def recorded(*aliases):
    return {"domain": "example.com", "aliases": list(aliases)}


# ── the ladder ───────────────────────────────────────────────────────────────


def test_the_postures_are_ordered_worst_last():
    assert rank("resolves") < rank("no_address") < rank("dangling")
    assert rank("dangling") < rank("claimable_service") < rank("unregistered_domain")


def test_an_unknown_posture_sorts_worst():
    """A verdict this file has not been taught about must fail loudly rather
    than pass quietly, or adding a verdict to the module silently disarms the
    gate for it."""
    assert rank("something_new") > rank(POSTURES[-1])


def test_every_posture_has_a_meaning_a_person_can_read():
    assert set(MEANINGS) >= set(POSTURES)


# ── regression: the thing the gate exists for ────────────────────────────────


def test_an_alias_getting_worse_is_a_regression():
    result = compare(
        [row("vpn.example.com", "claimable_service")],
        recorded(row("vpn.example.com", "dangling")),
    )
    assert result["ok"] is False
    assert result["regressions"][0]["observed"] == "claimable_service"
    assert result["regressions"][0]["recorded"] == "dangling"


def test_a_new_bad_alias_that_was_never_recorded_is_a_regression():
    """An unlisted alias is treated as expected-to-resolve, so the first time a
    dangling one appears the gate fires. That is the point of the file."""
    result = compare([row("new.example.com", "claimable_service")], recorded())
    assert result["ok"] is False
    assert result["regressions"][0]["known"] is False


def test_a_new_alias_that_resolves_is_not_a_regression():
    result = compare([row("www.example.com", "resolves")], recorded())
    assert result["ok"] is True
    assert result["regressions"] == []


def test_the_recorded_state_holds_the_build_green():
    """The known-and-recorded state must not fail. A gate that is permanently
    red for something the author of an unrelated change cannot fix is a gate
    people learn to click past — which is how the exposure gets missed."""
    result = compare(
        [row("vpn.example.com", "claimable_service")],
        recorded(row("vpn.example.com", "claimable_service")),
    )
    assert result["ok"] is True
    assert result["unchanged"][0]["observed"] == "claimable_service"


# ── improvement: reported, never silently absorbed ───────────────────────────


def test_an_alias_getting_better_is_reported_with_a_prompt_to_tighten():
    result = compare(
        [row("vpn.example.com", "dangling")],
        recorded(row("vpn.example.com", "claimable_service")),
    )
    assert result["ok"] is True
    assert result["improvements"][0]["observed"] == "dangling"


def test_a_recorded_alias_that_is_gone_entirely_is_an_improvement():
    """The record having been deleted is the outcome the gate is trying to
    produce, so it must be visible rather than just quietly absent."""
    result = compare([], recorded(row("vpn.example.com", "claimable_service")))
    assert result["improvements"][0]["observed"] == "absent"
    assert result["ok"] is True


def test_a_recorded_alias_that_resolved_all_along_and_is_gone_is_not_news():
    result = compare([], recorded(row("www.example.com", "resolves")))
    assert result["improvements"] == []


# ── unverified: not a pass ───────────────────────────────────────────────────


def test_an_unverified_alias_is_never_a_pass():
    """The resolver could not be trusted, so nothing was measured. Reporting
    green here would be exactly the false reassurance this whole file exists to
    prevent."""
    result = compare(
        [row("vpn.example.com", "unresolved", reason="negatives cannot be told apart")],
        recorded(row("vpn.example.com", "claimable_service")),
    )
    assert result["ok"] is False
    assert result["regressions"] == []
    assert result["unverified"][0]["reason"] == "negatives cannot be told apart"


def test_an_unverified_alias_is_not_counted_as_a_regression_either():
    """It is the absence of a measurement, not a measurement of something worse.
    Calling it a regression would send whoever reads the red build looking for a
    change that did not happen."""
    result = compare([row("vpn.example.com", "unresolved")], recorded())
    assert result["unverified"]
    assert result["regressions"] == []
    assert result["improvements"] == []


def test_an_unverified_row_still_says_what_was_recorded():
    result = compare(
        [row("vpn.example.com", "unresolved")],
        recorded(row("vpn.example.com", "claimable_service")),
    )
    assert result["unverified"][0]["recorded"] == "claimable_service"


# ── the rolled-up verdict and its exit codes ─────────────────────────────────


def test_a_clean_comparison_exits_zero():
    summary = summarise([compare([row("www.example.com", "resolves")], recorded())])
    assert (summary["verdict"], summary["exit_code"]) == ("held", 0)


def test_a_regression_exits_one():
    summary = summarise([compare([row("vpn.example.com", "dangling")], recorded())])
    assert (summary["verdict"], summary["exit_code"]) == ("regressed", 1)


def test_being_unable_to_verify_exits_two_not_zero():
    summary = summarise([compare([row("vpn.example.com", "unresolved")], recorded())])
    assert (summary["verdict"], summary["exit_code"]) == ("unverified", 2)


def test_a_regression_outranks_an_unverified_row():
    """Both are non-zero, but a known regression is the more actionable of the
    two and should be what the exit code names."""
    summary = summarise(
        [
            compare([row("a.example.com", "unresolved")], recorded()),
            compare([row("b.example.com", "claimable_service")], recorded()),
        ]
    )
    assert summary["exit_code"] == 1


def test_several_domains_roll_up_into_one_verdict():
    summary = summarise(
        [
            compare([row("a.example.com", "resolves")], recorded()),
            compare([row("b.example.com", "resolves")], {"domain": "other.com", "aliases": []}),
        ]
    )
    assert summary["exit_code"] == 0
    assert len(summary["domains"]) == 2


# ── the committed baseline is a real, usable file ────────────────────────────


def test_the_committed_baseline_parses_and_is_shaped_as_the_tool_expects():
    data = json.loads(BASELINE.read_text())
    assert data["domains"]
    for entry in data["domains"]:
        assert entry["domain"]
        for alias in entry.get("aliases", []):
            assert alias["host"].endswith(entry["domain"])
            assert alias["verdict"] in POSTURES
            assert alias["note"], "an entry without a reason decays into folklore"


def test_the_baseline_records_the_known_open_takeover():
    """Recorded at its true severity, so the gate is honest about where it
    starts and still fires if it worsens or a second one appears."""
    data = json.loads(BASELINE.read_text())
    aliases = [a for e in data["domains"] for a in e.get("aliases", [])]
    vpn = [a for a in aliases if a["host"] == "vpn.ironcityit.com"]
    assert vpn, "the live finding must stay recorded until it is actually fixed"
    assert vpn[0]["verdict"] == "claimable_service"


def test_the_committed_baseline_is_self_consistent_under_comparison():
    """Feeding the baseline back as the observation must be clean. If it is not,
    the file records something the comparison cannot express."""
    data = json.loads(BASELINE.read_text())
    for entry in data["domains"]:
        observed = [
            {"host": a["host"], "destination": a["destination"], "verdict": a["verdict"]}
            for a in entry.get("aliases", [])
        ]
        assert compare(observed, entry)["ok"] is True


# ── discovery coverage ───────────────────────────────────────────────────────


def full():
    return {
        "probe_names": 56,
        "certificate_transparency": "ok",
        "certificate_transparency_names": 9,
    }


def degraded():
    return {"probe_names": 56, "certificate_transparency": "unavailable"}


def test_coverage_is_carried_through_untouched():
    result = compare([row("www.example.com", "resolves")], recorded(), degraded())
    assert result["coverage"]["certificate_transparency"] == "unavailable"


def test_a_reduced_sweep_is_reported():
    summary = summarise([compare([], recorded(), degraded())])
    assert summary["reduced_coverage"][0]["domain"] == "example.com"


def test_a_reduced_sweep_does_not_fail_the_build_by_default():
    """Failing by default would put a third party's uptime in the path of every
    pull request, and a gate that goes red for reasons unrelated to the change is
    a gate people learn to click past."""
    summary = summarise([compare([], recorded(), degraded())])
    assert summary["exit_code"] == 0
    assert summary["verdict"] == "held"


def test_a_reduced_sweep_fails_when_it_is_asked_to():
    summary = summarise([compare([], recorded(), degraded())], strict_coverage=True)
    assert (summary["verdict"], summary["exit_code"]) == ("reduced_coverage", 2)


def test_a_full_sweep_is_never_reported_as_reduced():
    summary = summarise([compare([], recorded(), full())], strict_coverage=True)
    assert summary["reduced_coverage"] == []
    assert summary["exit_code"] == 0


def test_a_reduced_sweep_never_outranks_a_real_regression():
    """Both would exit non-zero, but a known regression is the more actionable
    finding and must be what the exit code names."""
    summary = summarise(
        [compare([row("vpn.example.com", "claimable_service")], recorded(), degraded())],
        strict_coverage=True,
    )
    assert (summary["verdict"], summary["exit_code"]) == ("regressed", 1)


def test_declining_certificate_transparency_is_not_reduced_coverage():
    coverage = {"probe_names": 56, "certificate_transparency": "not requested"}
    summary = summarise([compare([], recorded(), coverage)], strict_coverage=True)
    assert summary["reduced_coverage"] == []
    assert summary["exit_code"] == 0
