"""
Settings, read from the environment.

Field names are the environment variable names -- READ_ONLY, API_KEY, HOST,
DB_URL, DB_NAME -- with no prefix, matching the names that
deploy/systemd/api.env.example uses. Adding a prefix would silently
stop existing deployments from finding DB_URL.
"""
import re

from pydantic import field_validator
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

    # The path this service is mounted under when a reverse proxy puts it
    # somewhere other than a domain root: "/cryptomon" for
    # https://host/cryptomon/. Empty -- the default -- is the domain root,
    # which is what a direct `python api.py` wants and what every existing
    # deployment already has.
    #
    # It has to be told rather than detected. uvicorn 0.30's proxy-header
    # middleware handles X-Forwarded-For and X-Forwarded-Proto and has no
    # notion of a prefix at all, so nothing arriving on the wire carries one.
    # This value and the `location` in deploy/nginx/cryptomon.conf are a
    # pair; that file explains what each way of getting them out of step
    # looks like, and why nginx is configured to pass the URI unchanged
    # rather than strip the prefix.
    ROOT_PATH: str = ""

    @field_validator("ROOT_PATH")
    @classmethod
    def _plain_absolute_path(cls, value):
        """
        Normalise the prefix, and refuse one that is not a plain path.

        starlette strips the prefix with
        `re.sub(r"^" + root_path, "", scope["path"])` -- interpolated into a
        regular expression with no re.escape -- so a ROOT_PATH containing
        `.`, `+` or `(` silently matches paths it was never meant to match
        and routes them to the wrong handler, or to none. Refusing those
        characters makes that a startup failure with a message instead of a
        routing bug at run time.
        """
        value = value.strip().rstrip("/")
        if not value:
            return ""
        if not re.fullmatch(r"(/[A-Za-z0-9_-]+)+", value):
            raise ValueError(
                "ROOT_PATH must be a plain absolute path such as "
                "'/cryptomon': a leading slash, no trailing slash, and only "
                "letters, digits, underscore and hyphen in each segment. "
                "Got {0!r}.".format(value))
        return value


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
