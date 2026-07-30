"""
routes/discovery.py

OpenID Connect Discovery Endpoint

This endpoint mimics Microsoft's OpenID Configuration endpoint.

Reference:
https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration

For our simulator:

GET /.well-known/openid-configuration
"""

from fastapi import APIRouter

from app_config import settings

router = APIRouter()


@router.get(
    "/.well-known/openid-configuration",
    summary="OpenID Configuration",
    description="Returns the OpenID Connect discovery document."
)
async def openid_configuration():

    issuer = settings.ISSUER.rstrip("/")

    return {

        # ------------------------------------------------------------
        # Core Endpoints
        # ------------------------------------------------------------

        "issuer": issuer,

        "authorization_endpoint": f"{issuer}/oauth2/v2.0/authorize",

        "token_endpoint": f"{issuer}/oauth2/v2.0/token",

        "jwks_uri": f"{issuer}/.well-known/jwks.json",

        "userinfo_endpoint": f"{issuer}/oidc/userinfo",

        "end_session_endpoint": f"{issuer}/logout",

        # ------------------------------------------------------------
        # Supported OAuth2 Features
        # ------------------------------------------------------------

        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code id_token"
        ],

        "response_modes_supported": [
            "query",
            "fragment",
            "form_post"
        ],

        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token"
        ],

        # ------------------------------------------------------------
        # Scopes
        # ------------------------------------------------------------

        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "offline_access",
            "User.Read"
        ],

        # ------------------------------------------------------------
        # Subject Types
        # ------------------------------------------------------------

        "subject_types_supported": [
            "public"
        ],

        # ------------------------------------------------------------
        # Signing
        # ------------------------------------------------------------

        "id_token_signing_alg_values_supported": [
            "RS256"
        ],

        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic"
        ],

        # ------------------------------------------------------------
        # Claims
        # ------------------------------------------------------------

        "claims_supported": [

            "sub",

            "iss",

            "aud",

            "iat",

            "nbf",

            "exp",

            "name",

            "preferred_username",

            "email",

            "oid",

            "tid",

            "roles",

            "scp"
        ],

        # ------------------------------------------------------------
        # PKCE
        # ------------------------------------------------------------

        "code_challenge_methods_supported": [
            "S256",
            "plain"
        ]
    }