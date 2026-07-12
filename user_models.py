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
    phone = Column(String(20), unique=True, index=True, nullable=False)
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