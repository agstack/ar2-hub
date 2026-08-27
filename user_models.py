# SPDX-License-Identifier: EUPL-1.2
# Copyright (c) 2026 AgStack project contributors.
# Licensed under the EUPL, Version 1.2; see the LICENSE file for the full text.

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime, timezone

def get_utc_now():
    return datetime.now(timezone.utc)

from user_database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    
    email = Column(String(255), unique=True, index=True, nullable=False)
    # Nullable and non-unique on purpose. A UNIQUE NOT NULL phone encodes an
    # assumption that does not hold for this user base: a household or a
    # cooperative routinely shares one number, and some growers were registered
    # without one at all. Measured against the AR 1.0 population being migrated,
    # the constraint rejected 85 of 345 real accounts -- 8 with no phone and 77
    # sharing a number with another account. Dropping a quarter of the growers to
    # preserve a schema convenience is the wrong trade.
    #
    # email stays UNIQUE NOT NULL, which costs nothing: that same population has
    # zero missing and zero duplicate emails, so it remains a real identity
    # anchor and the one to authenticate against.
    phone = Column(String(20), unique=False, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    
    role = Column(String(50), nullable=True)
    country = Column(String(100), nullable=True)
    
    client_id = Column(String(50), unique=True, index=True, nullable=True)
    client_secret_hash = Column(String(255), nullable=True)
    
    registration_date = Column(DateTime, default=get_utc_now)
    is_active = Column(Boolean, default=True)

class SigningKey(Base):
    __tablename__ = "signing_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    public_key = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
    status = Column(String(50), default="active")

class SystemKey(Base):
    __tablename__ = "system_keys"

    id = Column(Integer, primary_key=True, index=True)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    created_at = Column(DateTime, default=get_utc_now)
    is_active = Column(Boolean, default=True)