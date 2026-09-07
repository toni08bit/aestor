from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    web_password: str = "change-me"
    session_secret: str = "change-me-session"
    api_bearer_token: str = "change-me-token"

    encryption_public_key_path: Path = Path("/keys/public.pem")
    download_dir: Path = Path("/data/downloads")
    completed_dir: Path = Path("/data/completed")

    # When true, skip VPN health gating (local / docker-compose.dev.yml)
    dev_mode: bool = False
    gluetun_control_url: str = "http://127.0.0.1:8001"

    host: str = "0.0.0.0"
    port: int = 8080

    # How often to poll gluetun / torrent progress (seconds)
    vpn_poll_interval: float = 5.0
    torrent_poll_interval: float = 0.5
    # WebSocket UI push interval
    live_push_interval: float = 0.35

    geoip_db_path: Path = Path("/usr/share/GeoIP/GeoLite2-Country.mmdb")

    session_cookie_name: str = "aestor_session"
    session_max_age: int = 60 * 60 * 24 * 7  # 7 days

    # ntfy (optional). Enabled when ntfy_enabled and ntfy_topic are set.
    ntfy_enabled: bool = False
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_token: str = ""
    ntfy_priority: int = 3
    # Comma-separated: completed,failed,vpn,all
    ntfy_events: str = "completed,failed,vpn"


@lru_cache
def get_settings() -> Settings:
    return Settings()
