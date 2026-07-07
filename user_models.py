# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from user_database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    
    email = Column(String(255), unique=True, index=True, nullable=False)
    phone = Column(String(20), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    
    client_id = Column(String(50), unique=True, index=True, nullable=True)
    client_secret_hash = Column(String(255), nullable=True)
    
    registration_date = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class SigningKey(Base):
    __tablename__ = "signing_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    public_key = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="active")

class SystemKey(Base):
    __tablename__ = "system_keys"

    id = Column(Integer, primary_key=True, index=True)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)