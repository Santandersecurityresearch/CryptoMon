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


class UploadSettings(BaseSettings):
    # The capture upload UI. On by default because the service binds
    # loopback (see ServerSettings), so the thing to opt into is exposure
    # rather than the feature. Turn it off for a deployment that only ever
    # serves the API.
    UPLOADS_ENABLED: bool = True
    # Where uploads are spooled and reports kept. Uploads are deleted as
    # soon as they are analysed; only the report remains.
    UPLOAD_DIR: str = "/tmp/cryptomon-uploads"
    # Enforced while the stream is read, not after -- see fapi/app/uploads.py.
    MAX_UPLOAD_BYTES: int = 256 * 1024 * 1024
    # Wall-clock ceiling for one analysis, passed to pcapscan.sandbox.
    ANALYSIS_TIMEOUT_SECONDS: int = 120


class RetentionSettings(BaseSettings):
    # A report holds SNI, which is browsing history. Reports expire by
    # default because nobody promised to keep them; the form says so before
    # the file is chosen. 0 disables expiry.
    REPORT_RETENTION_HOURS: int = 24
    RETENTION_SWEEP_MINUTES: int = 15
    # The live collection does *not* expire by default. Silently discarding a
    # monitoring database would destroy the historical series this project
    # exists to build, so retention there is opt-in. When set, it becomes a
    # MongoDB TTL index on `expires_at` -- see fapi/app/retention.py for why
    # it cannot simply expire on `ts`.
    DATA_RETENTION_HOURS: int = 0


class Settings(CommonSettings, ServerSettings, SecuritySettings,
               DatabaseSettings, UploadSettings, RetentionSettings):
    pass

settings = Settings()
