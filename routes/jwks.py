"""
routes/jwks.py

JSON Web Key Set (JWKS)

Microsoft Entra exposes

GET /.well-known/openid-configuration
GET /discovery/v2.0/keys

For Phase-1 we expose

GET /.well-known/jwks.json

Applications use this endpoint to validate JWT signatures.
"""

from fastapi import APIRouter

from security.rsa_keys import get_jwk

router = APIRouter()


@router.get(
    "/.well-known/jwks.json",
    summary="JWKS Endpoint",
    description="Returns the RSA Public Key in JSON Web Key Set format."
)
async def jwks():

    return {
        "keys": [
            get_jwk()
        ]
    }