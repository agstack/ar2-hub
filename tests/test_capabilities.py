# Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
# https://joinup.ec.europa.eu/software/page/eupl

"""The trace-forward capability is granted by the operator, not by the user.

Before this change ``generate_jwt`` wrote ``capabilities=["trace-forward"]``
into the token whenever ``role == "authority"``, and ``role`` was whatever the
user typed at registration. The first test here fails against that code.
"""

import os
import sys

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capabilities import ALLOWLIST_ENV, TRACE_FORWARD, authority_accounts, capabilities_for  # noqa: E402


# --- the pure function ------------------------------------------------------

def test_a_self_declared_role_grants_nothing():
    # No allowlist at all: nobody is an authority, whatever they called themselves.
    assert capabilities_for("anyone@example.org", env={}) == []


def test_an_allowlisted_account_gets_trace_forward():
    env = {ALLOWLIST_ENV: "fda.investigator@example.gov"}
    assert capabilities_for("fda.investigator@example.gov", env=env) == [TRACE_FORWARD]


def test_the_allowlist_is_case_and_whitespace_insensitive():
    env = {ALLOWLIST_ENV: " A@Example.org , b@example.org "}
    assert authority_accounts(env) == frozenset({"a@example.org", "b@example.org"})
    assert capabilities_for("a@EXAMPLE.org", env=env) == [TRACE_FORWARD]


def test_an_account_not_on_the_list_gets_nothing_even_when_the_list_is_set():
    env = {ALLOWLIST_ENV: "fda.investigator@example.gov"}
    assert capabilities_for("farmer@example.org", env=env) == []


def test_an_empty_or_blank_allowlist_means_nobody():
    assert capabilities_for("x@example.org", env={ALLOWLIST_ENV: ""}) == []
    assert capabilities_for("x@example.org", env={ALLOWLIST_ENV: " , , "}) == []


# --- the token the hub actually mints -----------------------------------------

@pytest.fixture(scope="module")
def rsa_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def _claims(token: str, pub: str) -> dict:
    return jwt.decode(token, pub, algorithms=["RS256"])


def test_generate_jwt_ignores_the_role_argument(monkeypatch, rsa_pem):
    """The control that matters: role="authority" must not produce the capability.

    This is the exact call the login routes make, with the exact value that
    used to unlock the capability.
    """
    monkeypatch.delenv(ALLOWLIST_ENV, raising=False)
    from hub_main import generate_jwt
    priv, pub = rsa_pem
    out = generate_jwt("self.declared@example.org", priv, role="authority")
    claims = _claims(out["access_token"], pub)
    assert "capabilities" not in claims, claims


def test_generate_jwt_grants_the_capability_from_the_allowlist(monkeypatch, rsa_pem):
    monkeypatch.setenv(ALLOWLIST_ENV, "fda.investigator@example.gov")
    from hub_main import generate_jwt
    priv, pub = rsa_pem
    out = generate_jwt("fda.investigator@example.gov", priv, role="farmer")
    claims = _claims(out["access_token"], pub)
    assert claims["capabilities"] == [TRACE_FORWARD]


def test_the_capability_check_can_fire(monkeypatch, rsa_pem):
    """Guard against the first test passing vacuously: the same decode path must
    be able to see a capability when one is present."""
    monkeypatch.setenv(ALLOWLIST_ENV, "seen@example.org")
    from hub_main import generate_jwt
    priv, pub = rsa_pem
    claims = _claims(generate_jwt("seen@example.org", priv)["access_token"], pub)
    assert claims.get("capabilities") == [TRACE_FORWARD]
