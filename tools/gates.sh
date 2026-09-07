#!/bin/sh
# Quality gates for DNS Guard.
#
# One script so a gate cannot pass on a developer's machine and fail in Jenkins
# for reasons nobody can reproduce. Jenkins calls each gate as its own stage
# (tools/gates.sh <gate>) so a red build names the gate that failed; a developer
# runs `tools/gates.sh all` and gets the same checks in the same order.
#
# POSIX sh, no bashisms: the same script has to run on the QNAP box, which is
# BusyBox.
#
# Exit codes: 0 pass, 1 fail, 2 usage. A gate whose tool is genuinely absent
# SKIPs loudly rather than passing silently — a skipped gate that reads as green
# is worse than no gate.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

REPORTS="${GATE_REPORTS:-$ROOT/gate-reports}"
mkdir -p "$REPORTS"

# Python packages this repo owns. Kept in one place so a new package is added
# to every gate at once.
SOURCES="dnsguard module_framework tools tests"

say()  { printf '\n=== %s ===\n' "$1"; }
skip() { printf 'SKIP: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

gate_lint() {
    say "lint (ruff check)"
    have ruff || fail "ruff is not installed; run: pip install -r requirements-dev.txt"
    # shellcheck disable=SC2086  # SOURCES is a path list; the splitting is the point
    ruff check $SOURCES
    printf 'lint clean\n'
}

gate_format() {
    say "format (ruff format --check)"
    have ruff || fail "ruff is not installed"
    # shellcheck disable=SC2086  # SOURCES is a path list; the splitting is the point
    ruff format --check $SOURCES
    printf 'formatting clean\n'
}

gate_typecheck() {
    say "typecheck (mypy)"
    have mypy || fail "mypy is not installed"
    mypy dnsguard module_framework tools
    printf 'types clean\n'
}

gate_test() {
    say "test (pytest)"
    have pytest || fail "pytest is not installed"
    # JUnit XML so Jenkins can render individual test results rather than a
    # single pass/fail blob.
    pytest tests \
        --junitxml="$REPORTS/junit.xml" \
        --cov=dnsguard --cov=module_framework \
        --cov-report="xml:$REPORTS/coverage.xml" \
        --cov-report=term:skip-covered
    printf 'tests passed\n'
}

# Every JSON artifact the pipeline produces has to satisfy the same three rules
# the scan workflow enforces before anything downstream consumes it.
gate_json() {
    say "json contract"
    found=0
    for file in $(find "$REPORTS" reports -maxdepth 2 -name '*.json' 2>/dev/null || true); do
        found=$((found + 1))
        first=$(head -c 1 "$file")
        [ "$first" = "{" ] || [ "$first" = "[" ] || fail "$file does not start with { or ["
        python3 -m json.tool "$file" > /dev/null || fail "$file is not valid JSON"
    done
    # Always prove the gate on a freshly generated report, so it is exercised
    # even on a clean checkout with no artifacts lying around.
    python3 tools/scan.py --domain example.com --client "Gate Check" --dry-run \
        -o "$REPORTS/scan" > /dev/null
    for file in "$REPORTS"/scan/*.json; do
        [ "$(head -c 1 "$file")" = "{" ] || fail "generated report does not start with {"
        python3 -m json.tool "$file" > /dev/null || fail "generated report is not valid JSON"
        found=$((found + 1))
    done
    printf 'validated %s JSON artifact(s)\n' "$found"
}

gate_yaml() {
    say "workflow yaml"
    # Distinguish "the parser is missing" from "the file is broken". Reporting
    # the second when it is the first sends whoever reads the log to the wrong
    # file, which is worse than no message at all.
    python3 -c "import yaml" 2>/dev/null \
        || fail "PyYAML is not installed; run: pip install -r requirements-dev.txt"
    for file in .github/workflows/*.yml; do
        python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1]))" "$file" \
            || fail "$file is not valid YAML"
        printf '  %s parses\n' "$file"
    done
    if have actionlint; then
        actionlint || fail "actionlint reported problems"
    else
        skip "actionlint not installed - YAML parsed but Actions semantics unchecked"
    fi
}

gate_node() {
    say "cloud function syntax"
    have node || { skip "node not installed"; return 0; }
    for file in cloud-function/*.js; do
        [ -f "$file" ] || continue
        node --check "$file" || fail "$file has a syntax error"
        printf '  %s parses\n' "$file"
    done
}

# Secret hygiene. Deliberately narrow: patterns that indicate a real credential
# committed by value, not every string that looks vaguely key-shaped. A noisy
# secret gate gets disabled, and a disabled gate finds nothing.
gate_secrets() {
    say "secret hygiene"
    hits=0
    # Provider token shapes. This list grew by one the hard way: a live-format
    # HubSpot private-app token sat in deploy.sh from January to September and
    # this gate reported "no committed credentials found" every single run,
    # because it only knew about AWS, PEM, GitHub and Slack. Add the shape when
    # a provider is adopted, not after the token leaks.
    patterns='
AKIA[0-9A-Z]{16}
-----BEGIN [A-Z ]*PRIVATE KEY-----
gh[pousr]_[A-Za-z0-9]{36}
xox[baprs]-[A-Za-z0-9-]{10,}
pat-(na|eu)[0-9]*-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
sk-[A-Za-z0-9]{32,}
AIza[0-9A-Za-z_-]{35}
glpat-[0-9A-Za-z_-]{20}
'
    # IFS is pinned to newline for this loop. Unquoted $patterns word-splits on
    # IFS, and the PEM pattern contains spaces — so it was never run as written.
    # It became four fragments, of which "-----BEGIN" matched any line
    # mentioning a PEM header (including a public certificate) and "[A-Z" is an
    # invalid bracket expression. That matters more than it looks: `if grep`
    # reads grep's error exit the same as "no match", so a malformed pattern
    # contributed nothing and said nothing. Hence the compile check below — a
    # gate that silently skips a rule is worse than one that never had it.
    old_ifs=$IFS
    IFS='
'
    for pattern in $patterns; do
        IFS=$old_ifs
        [ -n "$pattern" ] || continue
        # -e, always. A pattern starting with "-" is otherwise parsed as an
        # option: the PEM rule had been dying with "grep: unrecognized option"
        # since the day it was written, and `if grep` reads that exit the same
        # as "no match", so a committed private key would have passed this gate.
        printf '' | grep -qE -e "$pattern" 2>/dev/null || [ $? -eq 1 ] || \
            fail "secret pattern does not compile, so it was never applied: $pattern"
        IFS='
'
        # `apiKey:` is excluded, and only that. A Firebase *Web* API key is a
        # public client identifier: it ships to every browser that loads the
        # page, and it authorises nothing on its own - access is decided by the
        # security rules behind it. Treating it as a leaked secret would make
        # this gate cry wolf on a value that is public by design, and a gate
        # that cries wolf is one people learn to click past. Any other AIza
        # key - a server key, a Maps key - still fails here.
        if grep -rIEn --exclude-dir=.git --exclude-dir=gate-reports \
                --exclude-dir=node_modules --exclude=gates.sh -e "$pattern" . 2>/dev/null \
                | grep -vE '^\S+:[0-9]+:[[:space:]]*apiKey:'; then
            hits=$((hits + 1))
        fi
    done
    IFS=$old_ifs
    [ "$hits" -eq 0 ] || fail "possible committed credential - review the matches above"

    # Secrets must be referenced by name, never assigned a literal. This used to
    # look only inside .github/workflows/, which is why a literal in a shell
    # script at repo root was invisible to it. The whole tree is searched now.
    # ${NAME:-literal} counts: a default value is still a value in the file.
    if grep -rIEn --exclude-dir=.git --exclude-dir=gate-reports \
            --exclude-dir=node_modules --exclude=gates.sh \
            '(API_KEY|APIKEY|TOKEN|SECRET|SERVICE_ACCOUNT|PASSWORD|PASSWD|CREDENTIAL)[A-Z_]*[[:space:]]*[:=][[:space:]]*[\"'"'"']?[A-Za-z0-9/_+.-]{16,}' \
            . 2>/dev/null | grep -vE 'DNSGUARD_API_TOKEN|ci-build-token-not-a-real-secret|YOUR_|_HERE|example|placeholder|\$\{?[A-Za-z_]|secrets\.|env\.'; then
        fail "something assigns a secret literal - reference it by name instead"
    fi
    printf 'no committed credentials found\n'
}

# The dashboard is served as static files with no build step, so a syntax error
# in its inline script ships straight to a client's browser.
gate_dashboard() {
    say "dashboard syntax"
    have node || { skip "node not installed"; return 0; }
    for file in dashboard/public/*.html; do
        [ -f "$file" ] || continue
        case "$file" in *.backup|*.old) continue ;; esac
        python3 tools/extract_inline_js.py "$file" > "$REPORTS/inline.js" || fail "could not read $file"
        node --check "$REPORTS/inline.js" || fail "$file has a JavaScript syntax error"
        printf '  %s parses\n' "$file"
    done
}

# This script itself is shell that ships and runs on a BusyBox box. Nothing was
# checking it, which is how the SC2129 that broke the first CI run got written.
gate_shell() {
    say "gate script"
    have shellcheck || { skip "shellcheck not installed"; return 0; }
    shellcheck -s sh tools/gates.sh || fail "tools/gates.sh has shellcheck findings"
    printf 'gate script clean\n'
}

gate_build() {
    say "build"
    # The package must import from a clean interpreter with only the declared
    # dependencies - an import that works because of a stale sys.path is not a
    # build.
    python3 -c "
import dnsguard, dnsguard.api, dnsguard.policy, dnsguard.feeds, dnsguard.evidence
print('control plane imports:', dnsguard.__version__)
" || fail "the control plane does not import"
    python3 tools/scan.py --list-modules > "$REPORTS/catalog.json" || fail "the scanner does not run"
    python3 -m json.tool "$REPORTS/catalog.json" > /dev/null || fail "catalog is not valid JSON"
    printf 'modules discovered: %s\n' \
        "$(python3 -c "import json;print(len(json.load(open('$REPORTS/catalog.json'))['modules']))")"

    if have docker; then
        docker build -t icit-dnsguard:gate . || fail "docker build failed"
    else
        skip "docker not installed - Dockerfile not built"
    fi
}

gate_all() {
    gate_lint
    gate_format
    gate_typecheck
    gate_test
    gate_json
    gate_yaml
    gate_node
    gate_dashboard
    gate_secrets
    gate_shell
    gate_build
    say "all gates passed"
}

case "${1:-all}" in
    lint)      gate_lint ;;
    format)    gate_format ;;
    typecheck) gate_typecheck ;;
    test)      gate_test ;;
    json)      gate_json ;;
    yaml)      gate_yaml ;;
    node)      gate_node ;;
    dashboard) gate_dashboard ;;
    secrets)   gate_secrets ;;
    shell)     gate_shell ;;
    build)     gate_build ;;
    all)       gate_all ;;
    *)
        printf 'usage: %s [lint|format|typecheck|test|json|yaml|node|dashboard|secrets|shell|build|all]\n' "$0"
        exit 2
        ;;
esac
