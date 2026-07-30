"""
security/rsa_keys.py

RSA Key Management

Responsibilities
----------------
1. Generate RSA key pair (2048-bit by default)
2. Save keys under certs/
3. Load existing keys
4. Return keys for JWT signing
5. Return JWK for JWKS endpoint
"""

import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app_config import settings


class RSAKeyManager:
    """
    Handles generation, loading and access to RSA keys.
    """

    def __init__(self):

        self.private_key_path = Path(settings.PRIVATE_KEY_FILE)
        self.public_key_path = Path(settings.PUBLIC_KEY_FILE)

    # ------------------------------------------------------------------
    # Generate RSA Key Pair
    # ------------------------------------------------------------------

    def generate_keys(self):
        """
        Generates a new RSA key pair and saves it to disk.
        """

        private_key = rsa.generate_private_key(
            public_exponent=settings.RSA_PUBLIC_EXPONENT,
            key_size=settings.RSA_KEY_SIZE,
        )

        public_key = private_key.public_key()

        # Save private key
        with open(self.private_key_path, "wb") as private_file:

            private_file.write(

                private_key.private_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PrivateFormat.PKCS8,

                    encryption_algorithm=serialization.NoEncryption()

                )

            )

        # Save public key
        with open(self.public_key_path, "wb") as public_file:

            public_file.write(

                public_key.public_bytes(

                    encoding=serialization.Encoding.PEM,

                    format=serialization.PublicFormat.SubjectPublicKeyInfo

                )

            )

        print("RSA key pair generated successfully.")

    # ------------------------------------------------------------------
    # Initialize
    # ------------------------------------------------------------------

    def initialize(self):
        """
        Generates keys only if they don't already exist.
        """

        if (
            not self.private_key_path.exists()
            or
            not self.public_key_path.exists()
        ):
            self.generate_keys()

    # ------------------------------------------------------------------
    # Load Private Key
    # ------------------------------------------------------------------

    def load_private_key(self):

        with open(self.private_key_path, "rb") as private_file:

            return serialization.load_pem_private_key(

                private_file.read(),

                password=None

            )

    # ------------------------------------------------------------------
    # Load Public Key
    # ------------------------------------------------------------------

    def load_public_key(self):

        with open(self.public_key_path, "rb") as public_file:

            return serialization.load_pem_public_key(

                public_file.read()

            )


# ----------------------------------------------------------------------
# Singleton
# ----------------------------------------------------------------------

_key_manager = RSAKeyManager()


# ----------------------------------------------------------------------
# Public Functions
# ----------------------------------------------------------------------

def initialize_keys():
    """
    Initialize RSA keys during FastAPI startup.
    """

    _key_manager.initialize()


def get_private_key():
    """
    Returns loaded private key.
    """

    return _key_manager.load_private_key()


def get_public_key():
    """
    Returns loaded public key.
    """

    return _key_manager.load_public_key()


# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------

def _base64url_uint(value: int) -> str:
    """
    Converts an integer into Base64URL encoding without padding.
    """

    byte_length = (value.bit_length() + 7) // 8

    data = value.to_bytes(byte_length, byteorder="big")

    return (
        base64.urlsafe_b64encode(data)
        .rstrip(b"=")
        .decode("utf-8")
    )


# ----------------------------------------------------------------------
# JWK
# ----------------------------------------------------------------------

def get_jwk():
    """
    Returns the RSA public key in JSON Web Key (JWK) format.

    Used by:
        GET /.well-known/jwks.json
    """

    public_key = get_public_key()

    public_numbers = public_key.public_numbers()

    return {

        "kty": "RSA",

        "use": "sig",

        "alg": settings.JWT_ALGORITHM,

        "kid": settings.KEY_ID,

        "n": _base64url_uint(public_numbers.n),

        "e": _base64url_uint(public_numbers.e)

    }


# ----------------------------------------------------------------------
# PEM Export (Optional)
# ----------------------------------------------------------------------

def get_public_key_pem() -> str:
    """
    Returns public key in PEM format.
    """

    key = get_public_key()

    pem = key.public_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PublicFormat.SubjectPublicKeyInfo

    )

    return pem.decode("utf-8")


def get_private_key_pem() -> str:
    """
    Returns private key in PEM format.
    """

    key = get_private_key()

    pem = key.private_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PrivateFormat.PKCS8,

        encryption_algorithm=serialization.NoEncryption()

    )

    return pem.decode("utf-8")