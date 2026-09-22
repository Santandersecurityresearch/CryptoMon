"""
Settings, read from the environment.

Field names are the environment variable names -- READ_ONLY, API_KEY, HOST,
DB_URL, DB_NAME -- with no prefix, matching what create-service.sh already
writes into the systemd unit. Adding a prefix would silently stop existing
deployments from finding DB_URL.
"""
from pydantic_settings import BaseSettings

class CommonSettings(BaseSettings):
    APP_NAME: str = "Cryptomon API"
    DEBUG_MODE: bool = False

class ServerSettings(BaseSettings):
    # Loopback by default: exposure is opt-in. The previous 0.0.0.0 default
    # published an API with unauthenticated POST/PUT/DELETE to every interface
    # the moment it was started. Put it behind nginx to reach it remotely.
    HOST: str = "127.0.0.1"
    PORT: int = 8000


class SecuritySettings(BaseSettings):
    # Writes are refused unless an operator opts in, rather than allowed
    # unless an operator remembers to opt out. Set READ_ONLY=false to enable.
    READ_ONLY: bool = True
    # When set, mutating routes additionally require an X-API-Key header.
    API_KEY: str = ""

class DatabaseSettings(BaseSettings):
    DB_URL: str
    DB_NAME: str

class Settings(CommonSettings, ServerSettings, SecuritySettings,
               DatabaseSettings):
    pass

settings = Settings()
