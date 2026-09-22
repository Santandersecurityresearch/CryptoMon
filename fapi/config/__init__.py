#from pydantic_settings import BaseSettings
from pydantic import BaseSettings

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
    # unless an operator remembers to opt out.
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
