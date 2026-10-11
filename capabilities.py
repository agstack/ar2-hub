# Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
# https://joinup.ec.europa.eu/software/page/eupl

"""Which capabilities the hub writes into a token, and who decides.

Until 2026-10 the hub minted the ``trace-forward`` capability whenever a user's
``role`` was the string ``"authority"``. ``role`` is a free-text field the user
types at open registration, so the capability was self-assigned. The node still
demanded a verified grant or authority credential before disclosing anything, so
nothing leaked on the role alone -- but a permission anyone can give themselves
is not a permission, and a reader of the token could not tell the difference.

Capabilities now come from an operator-set allowlist and from nothing else.
``role`` remains a descriptive field and is not an authorisation input.
"""

import os

TRACE_FORWARD = "trace-forward"

# Comma-separated account emails the operator has accredited as authorities.
# Unset or empty means no account carries the capability, which is the safe
# default for a hub that has not been told who its authorities are.
ALLOWLIST_ENV = "HUB_AUTHORITY_ACCOUNTS"


def authority_accounts(env: dict | None = None) -> frozenset[str]:
    """The accredited account emails, lower-cased and stripped."""
    source = os.environ if env is None else env
    raw = source.get(ALLOWLIST_ENV, "") or ""
    return frozenset(
        item.strip().lower() for item in raw.split(",") if item.strip()
    )


def capabilities_for(email: str, env: dict | None = None) -> list[str]:
    """Capabilities to write into a token for ``email``.

    The caller's self-declared role is deliberately not a parameter: there is
    no way to pass it in, so there is no way to let it back in by accident.
    """
    if email and email.strip().lower() in authority_accounts(env):
        return [TRACE_FORWARD]
    return []
