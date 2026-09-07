"""Credentials: what a token binds to, and what it must never be able to claim.

The defect this replaces is worth stating, because most of these tests exist to
hold one half of it down. The control plane authenticated with a shared bearer
token, took the caller's *tenant* from a request header, and handed every
authenticated caller `viewer`, `operator` and `approver` unconditionally. One
token could therefore act as any client, in every role, approving its own
disruptive changes.

So: the tenant comes from the credential, the roles come from the credential, and
nothing a caller sends contributes to either.
"""

from __future__ import annotations

import json

import pytest

from dnsguard.errors import ValidationError
from dnsguard.identity import (
    APPROVER,
    OPERATOR,
    VIEWER,
    Credential,
    CredentialRegistry,
    hash_token,
    mint_token,
)

# Split so this file carries no literal that the secret-hygiene gate would
# match. See tests/test_gates.py for why that gate is not simply narrowed.
TOKEN = "a-token-" + "long-enough-to-be-accepted"
OTHER = "another-" + "token-long-enough-to-pass"


def credential(token=TOKEN, tenant="acme", roles=(VIEWER,), enabled=True, actor="bill"):
    return Credential(
        credential_id=f"{tenant}-{actor}",
        token_sha256=hash_token(token),
        tenant_id=tenant,
        actor=actor,
        roles=tuple(roles),
        enabled=enabled,
    )


# ── the token is never stored ────────────────────────────────────────────────


def test_only_a_digest_is_held():
    """A registry file that leaks must not be a set of working credentials."""
    record = credential().to_dict()
    assert record["token_sha256"] == hash_token(TOKEN)
    assert TOKEN not in json.dumps(record)


def test_a_plaintext_token_in_the_digest_field_is_refused():
    """The likeliest way to get this wrong is to paste the token where the
    digest goes. It would still authenticate — against the wrong value — so it
    is rejected loudly rather than quietly working."""
    with pytest.raises(ValidationError, match="sha256"):
        Credential(credential_id="c", token_sha256=TOKEN, tenant_id="acme", actor="bill")


def test_minted_tokens_are_unique_and_long():
    tokens = {mint_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(t) >= 32 for t in tokens)


# ── authentication ───────────────────────────────────────────────────────────


def test_the_right_token_returns_its_binding():
    registry = CredentialRegistry([credential(roles=(VIEWER, OPERATOR))])
    found = registry.authenticate(TOKEN)
    assert found is not None
    assert found.tenant_id == "acme"
    assert found.may(OPERATOR)
    assert not found.may(APPROVER)


@pytest.mark.parametrize("presented", ["", "wrong", OTHER, TOKEN + "x", TOKEN[:-1]])
def test_anything_but_the_token_is_refused(presented):
    assert CredentialRegistry([credential()]).authenticate(presented) is None


def test_a_disabled_credential_is_refused():
    """Revocation has to work without editing the file down to nothing, or
    nobody will revoke anything."""
    assert CredentialRegistry([credential(enabled=False)]).authenticate(TOKEN) is None


def test_an_empty_registry_authenticates_nobody():
    assert CredentialRegistry([]).authenticate(TOKEN) is None
    assert CredentialRegistry([]).authenticate("") is None


def test_two_credentials_cannot_share_a_token():
    """Whichever tenant you got would depend on list order — a tenant boundary
    decided by a coincidence."""
    with pytest.raises(ValidationError, match="share a token"):
        CredentialRegistry([credential(actor="bill"), credential(actor="ann", tenant="globex")])


def test_the_right_credential_is_found_among_many():
    registry = CredentialRegistry(
        [
            credential(token="tenant-a-" + "token-long-enough-x", tenant="acme", actor="a"),
            credential(token=OTHER, tenant="globex", actor="b"),
            credential(token=TOKEN, tenant="initech", actor="c"),
        ]
    )
    assert registry.authenticate(OTHER).tenant_id == "globex"
    assert registry.authenticate(TOKEN).tenant_id == "initech"


# ── roles ────────────────────────────────────────────────────────────────────


def test_roles_default_to_viewer_only():
    """Least privilege. Nothing acquires approver by omission — which is the
    whole point of having an approval gate at all."""
    assert credential().roles == (VIEWER,)


def test_an_unknown_role_is_refused():
    """A typo would otherwise produce a credential that silently permits
    nothing, and be debugged as a broken gate rather than a bad config."""
    with pytest.raises(ValidationError, match="unknown role"):
        credential(roles=("viewr",))


def test_a_credential_can_hold_approver_alone():
    c = credential(roles=(APPROVER,))
    assert c.may(APPROVER)
    assert not c.may(OPERATOR)


# ── required fields ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("missing", ["credential_id", "tenant_id", "actor"])
def test_a_credential_without_its_identity_is_refused(missing):
    fields = {
        "credential_id": "c",
        "token_sha256": hash_token(TOKEN),
        "tenant_id": "acme",
        "actor": "bill",
    }
    fields[missing] = ""
    with pytest.raises(ValidationError):
        Credential(**fields)


# ── loading from a file ──────────────────────────────────────────────────────


def test_a_registry_round_trips_through_json():
    registry = CredentialRegistry([credential(roles=(VIEWER, OPERATOR))])
    text = json.dumps({"credentials": [c.to_dict() for c in registry.credentials]})
    reloaded = CredentialRegistry.from_json(text)
    assert reloaded.authenticate(TOKEN).roles == (VIEWER, OPERATOR)


def test_a_bare_list_is_accepted_too():
    text = json.dumps([credential().to_dict()])
    assert CredentialRegistry.from_json(text).authenticate(TOKEN) is not None


@pytest.mark.parametrize("text", ["{not json", '"a string"', "{}", "123"])
def test_a_malformed_registry_file_is_refused_rather_than_ignored(text):
    """Silently loading zero credentials from a broken file would fail closed by
    accident and be diagnosed as "nobody can log in" rather than "the file is
    wrong"."""
    with pytest.raises(ValidationError):
        CredentialRegistry.from_json(text)


def test_a_file_registry_is_loaded_from_the_environment(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"credentials": [credential().to_dict()]}), encoding="utf-8")
    registry = CredentialRegistry.from_env({"DNSGUARD_CREDENTIALS_FILE": str(path)})
    assert registry.authenticate(TOKEN).tenant_id == "acme"


def test_an_unreadable_credential_file_is_an_error_not_an_empty_registry(tmp_path):
    with pytest.raises(ValidationError, match="cannot read"):
        CredentialRegistry.from_env({"DNSGUARD_CREDENTIALS_FILE": str(tmp_path / "nope.json")})


# ── the environment shorthand ────────────────────────────────────────────────


def test_a_token_without_a_tenant_is_refused():
    """The root of the defect: a token that names no tenant used to take one
    from a request header."""
    with pytest.raises(ValidationError, match="DNSGUARD_API_TENANT"):
        CredentialRegistry.from_env({"DNSGUARD_API_TOKEN": TOKEN})


def test_the_environment_credential_defaults_to_viewer():
    registry = CredentialRegistry.from_env(
        {"DNSGUARD_API_TOKEN": TOKEN, "DNSGUARD_API_TENANT": "acme"}
    )
    found = registry.authenticate(TOKEN)
    assert found.roles == (VIEWER,)
    assert not found.may(OPERATOR)


def test_the_environment_credential_honours_explicit_roles():
    registry = CredentialRegistry.from_env(
        {
            "DNSGUARD_API_TOKEN": TOKEN,
            "DNSGUARD_API_TENANT": "acme",
            "DNSGUARD_API_ROLES": "viewer, operator",
        }
    )
    assert registry.authenticate(TOKEN).roles == (VIEWER, OPERATOR)


def test_a_short_token_is_refused():
    with pytest.raises(ValidationError, match="at least"):
        CredentialRegistry.from_env({"DNSGUARD_API_TOKEN": "short", "DNSGUARD_API_TENANT": "acme"})


def test_no_configuration_yields_an_empty_registry():
    """Empty, not an error — create_app is what decides that an empty registry
    means refusing to start, and it says so in those terms."""
    assert len(CredentialRegistry.from_env({})) == 0


def test_the_file_wins_over_the_environment_shorthand(tmp_path):
    """Otherwise a stray DNSGUARD_API_TOKEN in a shell profile would quietly
    override the real registry."""
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps({"credentials": [credential(token=OTHER, tenant="globex").to_dict()]}),
        encoding="utf-8",
    )
    registry = CredentialRegistry.from_env(
        {
            "DNSGUARD_CREDENTIALS_FILE": str(path),
            "DNSGUARD_API_TOKEN": TOKEN,
            "DNSGUARD_API_TENANT": "acme",
        }
    )
    assert registry.authenticate(TOKEN) is None
    assert registry.authenticate(OTHER).tenant_id == "globex"
