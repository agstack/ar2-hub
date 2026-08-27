# SPDX-License-Identifier: EUPL-1.2
# Copyright (c) 2026 AgStack project contributors.
# Licensed under the EUPL, Version 1.2; see the LICENSE file for the full text.

import sys
import jwt

def verify_token(token: str, jwks_url: str):
    jwks_client = jwt.PyJWKClient(jwks_url)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"]
        )
        print("Token is valid!")
        print("Payload:", data)
        return True
    except jwt.exceptions.PyJWTError as e:
        print("Token validation failed:", e)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_jwt.py <jwt_token> <jwks_url>")
        print("Example: python verify_jwt.py eyJhb... http://127.0.0.1:8000/.well-known/jwks.json")
        sys.exit(1)
        
    token = sys.argv[1]
    jwks_url = sys.argv[2]
    
    success = verify_token(token, jwks_url)
    if not success:
        sys.exit(1)
