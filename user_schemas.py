# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import bcrypt
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    email: EmailStr
    phone: str = Field(
        ..., 
        description="Must be in E.164 international format (e.g., +1234567890)"
    )

    @field_validator('phone')
    def validate_international_phone(cls, v):
        v = v.strip()
        if not v.startswith('+'):
            raise ValueError("Phone number must include international country code starting with '+'")
        if not v[1:].isdigit():
            raise ValueError("Phone number must contain only digits after the '+' sign")
        if len(v) < 8 or len(v) > 16:
            raise ValueError("Invalid phone number length")
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Minimum 8 characters")

    def get_hashed_password(self) -> str:
        """Helper function to securely hash the password before DB insertion."""
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(self.password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

class UserResponse(UserBase):
    id: int
    registration_date: datetime
    is_active: bool

    class Config:
        from_attributes = True