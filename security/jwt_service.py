"""
security/jwt_service.py

JWT Service

Responsibilities
----------------
1. Generate RS256 Access Tokens
2. Generate ID Tokens (optional)
3. Validate Tokens
4. Decode Tokens
5. Support Custom Claims
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidTokenError,
)

from app_config import settings
from security.rsa_keys import (
        initialize_keys,
        get_private_key,
        get_public_key,
)




class JWTService:

    def __init__(self):
        initialize_keys()

        self.private_key = get_private_key()
        self.public_key = get_public_key()

    # ------------------------------------------------------------
    # Base Claims
    # ------------------------------------------------------------

    def _base_claims(
        self,
        username: str,
        expires_in: int,
        scopes: List[str],
        roles: List[str],
    ) -> Dict:

        now = datetime.now(timezone.utc)

        exp = now + timedelta(seconds=expires_in)

        return {

            "iss": settings.ISSUER,

            "aud": settings.AUDIENCE,

            "sub": username,

            "name": username,

            "preferred_username": username,

            "email": username,

            "oid": settings.DEFAULT_OBJECT_ID,

            "tid": settings.DEFAULT_TENANT_ID,

            "scp": " ".join(scopes),

            "roles": roles,

            "iat": int(now.timestamp()),

            "nbf": int(now.timestamp()),

            "exp": int(exp.timestamp()),
        }

    # ------------------------------------------------------------
    # Generate Access Token
    # ------------------------------------------------------------

    def generate_access_token(
        self,
        username: str,
        scopes: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        expires_in: Optional[int] = None,
        additional_claims: Optional[Dict] = None,
    ) -> str:

        if scopes is None:
            scopes = [settings.DEFAULT_SCOPE]

        if roles is None:
            roles = settings.DEFAULT_ROLES

        if expires_in is None:
            expires_in = settings.TOKEN_EXPIRY_SECONDS

        payload = self._base_claims(
            username=username,
            expires_in=expires_in,
            scopes=scopes,
            roles=roles,
        )

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=settings.JWT_ALGORITHM,
            headers={
                "kid": settings.KEY_ID,
                "typ": "JWT",
            },
        )

        return token

    # ------------------------------------------------------------
    # Decode Token
    # ------------------------------------------------------------

    def decode_token(self, token: str):

        return jwt.decode(
            token,
            self.public_key,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.AUDIENCE,
            issuer=settings.ISSUER,
        )

    # ------------------------------------------------------------
    # Validate Token
    # ------------------------------------------------------------

    def validate_token(self, token: str):

        try:

            claims = self.decode_token(token)

            return {

                "valid": True,

                "claims": claims,

                "message": "Token is valid"

            }

        except ExpiredSignatureError:

            return {

                "valid": False,

                "message": "Token has expired"

            }

        except InvalidTokenError as ex:

            return {

                "valid": False,

                "message": str(ex)

            }

    # ------------------------------------------------------------
    # Generate Expired Token
    # ------------------------------------------------------------

    def generate_expired_token(
        self,
        username: str,
    ):

        return self.generate_access_token(
            username=username,
            expires_in=-300,
        )

    # ------------------------------------------------------------
    # Generate Future Token
    # ------------------------------------------------------------

    def generate_future_token(
        self,
        username: str,
    ):

        now = datetime.now(timezone.utc)

        payload = {

            "iss": settings.ISSUER,

            "aud": settings.AUDIENCE,

            "sub": username,

            "preferred_username": username,

            "iat": int((now + timedelta(hours=2)).timestamp()),

            "nbf": int((now + timedelta(hours=2)).timestamp()),

            "exp": int((now + timedelta(hours=3)).timestamp()),

        }

        return jwt.encode(
            payload,
            self.private_key,
            algorithm=settings.JWT_ALGORITHM,
            headers={
                "kid": settings.KEY_ID
            }
        )


# ------------------------------------------------------------
# Singleton
# ------------------------------------------------------------

jwt_service = JWTService()