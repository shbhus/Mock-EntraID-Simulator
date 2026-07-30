"""
app_config.py

Configuration for the Mock Microsoft Entra ID Simulator.
"""

from pathlib import Path


class Settings:
    """
    Central configuration for the simulator.
    """

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    APP_NAME = "Mock Microsoft Entra ID Simulator"
    VERSION = "1.0.0"

    HOST = "0.0.0.0"
    PORT = 8080

    DEBUG = True

    # ------------------------------------------------------------------
    # Project Directories
    # ------------------------------------------------------------------

    BASE_DIR = Path(__file__).resolve().parent

    CERT_DIR = BASE_DIR / "certs"
    LOG_DIR = BASE_DIR / "logs"
    DATA_DIR = BASE_DIR / "data"

    # ------------------------------------------------------------------
    # RSA Keys
    # ------------------------------------------------------------------

    PRIVATE_KEY_FILE = CERT_DIR / "private.pem"
    PUBLIC_KEY_FILE = CERT_DIR / "public.pem"

    RSA_KEY_SIZE = 2048
    RSA_PUBLIC_EXPONENT = 65537

    # ------------------------------------------------------------------
    # JWT Configuration
    # ------------------------------------------------------------------

    JWT_ALGORITHM = "RS256"

    TOKEN_EXPIRY_SECONDS = 3600

    ISSUER = "http://localhost:8080"

    AUDIENCE = "mock-client"

    KEY_ID = "mock-entra-key"

    # ------------------------------------------------------------------
    # Default Claims
    # ------------------------------------------------------------------

    DEFAULT_TENANT_ID = "11111111-1111-1111-1111-111111111111"

    DEFAULT_OBJECT_ID = "22222222-2222-2222-2222-222222222222"

    DEFAULT_SCOPE = "User.Read"

    DEFAULT_ROLES = [
        "User"
    ]

    # ------------------------------------------------------------------
    # Default User
    # ------------------------------------------------------------------

    DEFAULT_USERNAME = "admin@test.com"

    DEFAULT_NAME = "Automation Tester"

    DEFAULT_EMAIL = "admin@test.com"

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    OPENID_CONFIGURATION_ENDPOINT = "/.well-known/openid-configuration"

    JWKS_ENDPOINT = "/.well-known/jwks.json"

    TOKEN_ENDPOINT = "/generate-token"

    HEALTH_ENDPOINT = "/health"

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    LOG_LEVEL = "INFO"

    LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"

    # ------------------------------------------------------------------
    # Directory Initialization
    # ------------------------------------------------------------------

    @classmethod
    def create_directories(cls):
        """
        Create required directories if they do not exist.
        """

        cls.CERT_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOG_DIR.mkdir(parents=True, exist_ok=True)
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------
# Singleton Settings Object
# ----------------------------------------------------------

settings = Settings()

# Create required folders during startup
Settings.create_directories()