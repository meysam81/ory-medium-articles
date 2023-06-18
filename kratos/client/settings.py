from pathlib import Path

from pydantic import BaseSettings, root_validator
from utils import generate_random_string


class Settings(BaseSettings):
    APP_NAME: str = "Kratos Client"
    APP_FULL_HOST: str | None
    PORT: int = 3000
    HOST: str = "localhost"
    SCHEME: str = "http"
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = True

    KRATOS_PUBLIC_URL: str = "http://localhost:4433"

    KRATOS_LOGIN_BROWSER_URI: str = "/self-service/login/browser"
    KRATOS_LOGIN_FLOW_URI: str = "/self-service/login/flows"

    KRATOS_VERIFICATION_BROWSER_URI: str = "/self-service/verification/browser"
    KRATOS_VERIFICATION_FLOW_URI: str = "/self-service/verification/flows"

    KRATOS_REGISTRATION_BROWSER_URI: str = "/self-service/registration/browser"
    KRATOS_REGISTRATION_FLOW_URI: str = "/self-service/registration/flows"

    KRATOS_LOGOUT_BROWSER_URI: str = "/self-service/logout/browser"

    KRATOS_RECOVERY_BROWSER_URI: str = "/self-service/recovery/browser"
    KRATOS_RECOVERY_FLOW_URI: str = "/self-service/recovery/flows"

    KRATOS_SETTINGS_BROWSER_URI: str = "/self-service/settings/browser"
    KRATOS_SETTINGS_FLOW_URI: str = "/self-service/settings/flows"

    KRATOS_WHOAMI_URI: str = "/sessions/whoami"

    INDEX_URI: str = "/"
    LOGIN_URI: str = "/login"
    VERIFICATION_URI: str = "/verification"
    REGISTRATION_URI: str = "/registration"
    LOGOUT_URI: str = "/logout"
    RECOVERY_URI: str = "/recovery"
    SETTINGS_URI: str = "/settings"
    ERROR_URI: str = "/error"

    CSRF_TOKEN_LENTGH: int = 32
    CSRF_ENCRYPTION_KEY_PATH: str = "/tmp/csrf_encryption_key"
    CSRF_ENCRYPTION_KEY: bytes | None
    CSRF_ENCRYPTION_KEY_SIZE: int = 32
    CSRF_ENCRYPTION_ALGORITHM: str = "AES"
    CSRF_TOKEN_COOKIE_NAME: str = "kratos_client_csrf_token"

    @root_validator
    def validate_settings(cls, values):
        if not values["APP_FULL_HOST"]:
            values[
                "APP_FULL_HOST"
            ] = f"{values['SCHEME']}://{values['HOST']}:{values['PORT']}"

        if not values["CSRF_ENCRYPTION_KEY"]:
            key_path = Path(values["CSRF_ENCRYPTION_KEY_PATH"])

            if not (key_path.exists() and key_path.stat().st_size):
                csrf_key = generate_random_string(values["CSRF_ENCRYPTION_KEY_SIZE"])
                key_path.write_text(csrf_key)
            else:
                csrf_key = key_path.read_text()

            values["CSRF_ENCRYPTION_KEY"] = csrf_key.encode()

        return values


settings = Settings()
