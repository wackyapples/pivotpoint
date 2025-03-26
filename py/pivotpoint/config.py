from dataclasses import dataclass, field, asdict
from typing import Any
from pathlib import Path
import tomllib as toml

import slog

@dataclass
class RedirectConfig:
    source_domain: str
    target_url: str
    redirect_type: int = 301
    preserve_path: bool = True
    https_first: bool = True


@dataclass
class CertConfig:
    domain: str
    cert_file: str
    key_file: str


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    http_port: int = 80
    https_port: int = 443
    log_level: str = "INFO"


ConfigTuple = tuple[list[RedirectConfig], list[CertConfig], ServerConfig]


def parse_config(
    config_path: str | Path,
) -> ConfigTuple:
    if isinstance(config_path, str):
        config_path = Path(config_path)
    
    with config_path.open("rb") as f:
        config = toml.load(f)
    
    # Validate required sections
    required_sections = ["redirects", "certificates"]
    missing_sections = [sect for sect in required_sections if sect not in config]
    if missing_sections:
        slog.error(f"Missing required config sections", missing_sections=missing_sections)
        return None, None, None
    
    # Parse with defaults
    redirects = [RedirectConfig(**redirect) for redirect in config["redirects"]]
    certs = [CertConfig(**cert) for cert in config["certificates"]]
    server_config = ServerConfig(**(config.get("server", {})))
    
    return redirects, certs, server_config

def merge_server_config(server_config: ServerConfig, config: dict[str, Any]) -> ServerConfig:
    return ServerConfig(
        **{**asdict(server_config), **config}
    )
