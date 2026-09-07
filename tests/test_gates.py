"""The secret-hygiene gate, tested against planted credentials.

This gate reported "no committed credentials found" on every run for eight
months while a live-format HubSpot token sat in `deploy.sh` at the repository
root. It was not broken — it was narrow, in two ways nobody had cause to notice:
its pattern list knew about four providers, and its literal-assignment check
looked only inside `.github/workflows/`.

A gate that asserts a negative is exactly the kind that needs its own test. So
each case here plants a credential shape and requires the gate to fail, and the
last case plants a value that is public by design and requires it to pass —
because a gate that cries wolf gets clicked past, which is the same outcome as
having no gate at all.

Every planted value is synthetic. Real-looking shape, all-zero payload.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GATES = ROOT / "tools" / "gates.sh"


def run_gate(tmp_path: Path, filename: str, content: str) -> subprocess.CompletedProcess:
    """Run the real gate over a tree containing exactly one planted file.

    `gates.sh` resolves its own root from its location, so the script is copied
    into `tmp/tools/` and the fixture written beside it at `tmp/`. That is the
    same layout as the repository, and it means the gate under test is the
    shipped one rather than a copy of its logic.
    """
    (tmp_path / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copy(GATES, tmp_path / "tools" / "gates.sh")
    (tmp_path / filename).write_text(content, encoding="utf-8")
    return subprocess.run(
        ["sh", str(tmp_path / "tools" / "gates.sh"), "secrets"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )


# Every planted shape is ASSEMBLED AT RUNTIME rather than written out, so this
# file contains no string that the gate would match. That is not a trick to
# dodge the gate — it is the only way to test a repository-wide scanner from
# inside the repository it scans. `test_this_file_is_itself_clean` holds the
# line: if a fixture is ever written out literally, that test fails.
#
# A real Google API key is "AIza" plus 35 characters. One short and the pattern
# does not match — which is how the first draft of this test passed against a
# gate that was working correctly. The length is the point, so it is built.
GOOGLE_KEY = "AIza" + "SyA" + "0" * 32
HUBSPOT_KEY = "pat-" + "na2-" + "0" * 8 + "-1111-2222-3333-" + "4" * 12
AWS_KEY = "AKIA" + "Z" * 16
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE " + "KEY" + "-----"
SLACK_TOKEN = "xox" + "b-" + "0" * 10 + "-" + "a" * 10
GITHUB_PAT = "gh" + "p_" + "a" * 36
OPENAI_KEY = "sk" + "-" + "a" * 32
GITLAB_PAT = "glp" + "at-" + "a" * 20
PASSWORD_LITERAL = "DB_PASS" + "WORD = " + '"' + "s3cretvalue_thatis_long_enough" + '"'

PLANTED = [
    pytest.param(
        "deploy.sh",
        "HUBSPOT_API" + '_KEY="${HUBSPOT_API_KEY:-' + HUBSPOT_KEY + '}"\n',
        id="the shape that was actually missed, in the place it was missed",
    ),
    pytest.param(
        "settings.py",
        PASSWORD_LITERAL + "\n",
        id="a literal outside .github/workflows, where the old check never looked",
    ),
    pytest.param("conf.env", f"GOOGLE_MAPS_SERVER_KEY={GOOGLE_KEY}\n", id="google server key"),
    pytest.param("id_rsa", PEM_HEADER + "\n", id="pem private key"),
    pytest.param("ci.sh", f"export AWS_KEY={AWS_KEY}\n", id="aws access key id"),
    pytest.param("notes.md", f"token: {GITHUB_PAT}\n", id="github personal access token"),
    pytest.param("hook.py", f'URL = "https://x/{SLACK_TOKEN}"\n', id="slack token"),
    pytest.param("app.js", f'const k = "{OPENAI_KEY}";\n', id="openai-style key"),
    pytest.param("gitlab.yml", f"GLPAT: {GITLAB_PAT}\n", id="gitlab pat"),
]


@pytest.mark.parametrize(
    ("filename", "content"),
    [(p.values[0], p.values[1]) for p in PLANTED],
    ids=[p.id for p in PLANTED],
)
def test_the_gate_fails_on_a_planted_credential(tmp_path, filename, content):
    result = run_gate(tmp_path, filename, content)
    assert result.returncode != 0, (
        f"the gate passed with {filename} planted — it reports a negative, "
        f"so a miss is silent:\n{result.stdout}"
    )
    assert "FAIL" in result.stdout


def test_a_firebase_web_api_key_does_not_trip_the_gate(tmp_path):
    """Public by design. It ships to every browser that loads the page and
    authorises nothing on its own — access is decided by the rules behind it.
    Failing on it would make the gate cry wolf on a value that is meant to be
    published, and a gate people click past catches nothing."""
    content = f'const firebaseConfig = {{\n  apiKey: "{GOOGLE_KEY}",\n  projectId: "x"\n}};\n'
    result = run_gate(tmp_path, "index.html", content)
    assert result.returncode == 0, f"false positive on a public web config:\n{result.stdout}"
    assert "no committed credentials found" in result.stdout


def test_the_allowance_is_narrow_enough_to_still_catch_a_server_key(tmp_path):
    """The exemption is keyed on `apiKey:` specifically. The same value under
    any other name must still fail, or the allowance becomes a way to smuggle
    one past."""
    content = f'const c = {{\n  serverKey: "{GOOGLE_KEY}"\n}};\n'
    result = run_gate(tmp_path, "index.html", content)
    assert result.returncode != 0


def test_a_clean_tree_passes(tmp_path):
    """The gate has to be able to say yes, or the cases above prove nothing."""
    result = run_gate(tmp_path, "app.py", "TOKEN = os.environ['DNSGUARD_API_TOKEN']\n")
    assert result.returncode == 0, result.stdout
    assert "no committed credentials found" in result.stdout


def test_a_named_reference_is_not_mistaken_for_a_literal(tmp_path):
    """Referencing a secret by name is the practice the gate exists to enforce.
    Flagging it would punish exactly the thing it is asking for."""
    content = (
        "API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}\n"
        "TOKEN = os.environ.get('DNSGUARD_API_TOKEN', '')\n"
        'PASSWORD="${DB_PASSWORD}"\n'
    )
    result = run_gate(tmp_path, "workflow.yml", content)
    assert result.returncode == 0, result.stdout


def test_the_shipped_repository_is_clean():
    """The real tree, through the real gate. This is the assertion the other
    tests exist to make trustworthy."""
    result = subprocess.run(
        ["sh", str(GATES), "secrets"], capture_output=True, text=True, cwd=str(ROOT)
    )
    assert result.returncode == 0, result.stdout


def test_this_file_is_itself_clean(tmp_path):
    """The fixtures above are assembled at runtime precisely so that this file
    carries no matching literal. If somebody later writes one out inline, the
    repository-wide gate would start failing on its own test data — and the
    obvious fix would be to exclude tests/ from the scan, which would hand a
    real secret somewhere to hide. This fails first instead, and says why."""
    result = run_gate(tmp_path, "test_gates.py", Path(__file__).read_text(encoding="utf-8"))
    assert result.returncode == 0, (
        "a planted shape is written out literally in this file. Assemble it at "
        f"runtime instead — do not exclude tests/ from the gate:\n{result.stdout}"
    )
