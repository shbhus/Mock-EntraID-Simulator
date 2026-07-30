"""
routes/token.py

Token Generation Endpoint

Endpoints
---------
POST /generate-token

Generates an RS256 signed JWT similar to Microsoft Entra ID.
"""

from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from security.jwt_service import jwt_service

router = APIRouter()


# ============================================================
# Request Model
# ============================================================

class TokenRequest(BaseModel):
    """
    Request body for token generation.
    """

    username: str = Field(
        ...,
        example="admin@test.com",
        description="User principal name"
    )

    roles: Optional[List[str]] = Field(
        default=["User"],
        example=["Admin", "Manager"]
    )

    scopes: Optional[List[str]] = Field(
        default=["User.Read"],
        example=["User.Read", "Files.Read"]
    )

    expires_in: Optional[int] = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Token validity in seconds"
    )

    additional_claims: Optional[Dict] = Field(
        default_factory=dict,
        example={
            "department": "QA",
            "country": "India"
        }
    )


# ============================================================
# Response Model
# ============================================================

class TokenResponse(BaseModel):

    access_token: str

    token_type: str

    expires_in: int


# ============================================================
# Generate Token
# ============================================================

@router.post(
    "/generate-token",
    response_model=TokenResponse,
    summary="Generate JWT Access Token",
    description="Generate Microsoft Entra compatible Bearer Token."
)
async def generate_token(request: TokenRequest):

    try:

        token = jwt_service.generate_access_token(

            username=request.username,

            roles=request.roles,

            scopes=request.scopes,

            expires_in=request.expires_in,

            additional_claims=request.additional_claims

        )

        return TokenResponse(

            access_token=token,

            token_type="Bearer",

            expires_in=request.expires_in

        )

    except Exception as ex:

        raise HTTPException(

            status_code=500,

            detail=str(ex)

        )


# ============================================================
# Generate Expired Token
# ============================================================

@router.post(
    "/generate-expired-token",
    summary="Generate Expired Token"
)
async def generate_expired_token(request: TokenRequest):

    token = jwt_service.generate_expired_token(
        username=request.username
    )

    return {

        "access_token": token,

        "token_type": "Bearer",

        "expires_in": -300

    }


# ============================================================
# Validate Token
# ============================================================

@router.post(
    "/validate-token",
    summary="Validate JWT Token"
)
async def validate_token(token: str):

    result = jwt_service.validate_token(token)

    return result


# ============================================================
# Decode Token
# ============================================================

@router.post(
    "/decode-token",
    summary="Decode JWT"
)
async def decode_token(token: str):

    try:

        claims = jwt_service.decode_token(token)

        return claims

    except Exception as ex:

        raise HTTPException(

            status_code=400,

            detail=str(ex)

        )