# Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
# https://joinup.ec.europa.eu/software/page/eupl

import bcrypt
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    email: EmailStr
    phone: Optional[str] = Field(
        None,
        description="Optional. If given, must be in E.164 international format (e.g., +1234567890)"
    )
    role: Optional[str] = None
    country: Optional[str] = None

    @field_validator('phone')
    def validate_international_phone(cls, v):
        # Optional, but still validated when present: accepting a malformed
        # number is not the same concession as accepting no number.
        if v is None or v.strip() == "":
            return None
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
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(self.password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

class UserResponse(UserBase):
    id: int
    registration_date: datetime
    is_active: bool

    class Config:
        from_attributes = True

class UserRegistrationResponse(UserResponse):
    client_id: str
    client_secret: str

class SigningKeyCreate(BaseModel):
    public_key: str = Field(..., description="The Ed25519 public key in Base64 or Hex")

class SigningKeyResponse(BaseModel):
    id: int
    user_id: int
    public_key: str
    created_at: datetime
    status: str

    class Config:
        from_attributes = True