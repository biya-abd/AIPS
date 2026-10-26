"""
Configuration loading and validation for AIPS.

All runtime configuration comes from environment variables (loaded from
.env via python-dotenv). Nothing here is hardcoded as an application
constant per the project requirements. If a required value is missing,
startup fails loudly rather than silently falling back to an insecure
default.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"

load_dotenv(ENV_PATH)


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _parse_allowlist(raw: str) -> tuple:
    always = {"127.0.0.1", "::1"}
    given = {x.strip() for x in raw.split(",") if x.strip()}
    return tuple(sorted(always | given))


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val)
    except ValueError:
        print(f"[config] WARNING: {name}='{val}' is not an integer, using default {default}", file=sys.stderr)
        return default


@dataclass
class Config:
    # AI / OpenRouter
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    openrouter_base_url: str = field(default_factory=lambda: os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))
    openrouter_model: str = field(default_factory=lambda: os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b"))
    ai_enabled: bool = field(default_factory=lambda: _get_bool("AI_ENABLED", True))
    ai_timeout_seconds: int = field(default_factory=lambda: _get_int("AI_TIMEOUT_SECONDS", 20))
    ai_max_retries: int = field(default_factory=lambda: _get_int("AI_MAX_RETRIES", 1))

    # Server
    host: str = field(default_factory=lambda: os.getenv("AIPS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _get_int("AIPS_PORT", 8080))
    mode: str = field(default_factory=lambda: os.getenv("AIPS_MODE", "monitor"))

    # Database
    db_path: str = field(default_factory=lambda: os.getenv("AIPS_DB_PATH", "./data/aips.db"))

    # Target
    target_bind_scope: str = field(default_factory=lambda: os.getenv("TARGET_BIND_SCOPE", "unknown"))
    target_access_log_path: str = field(default_factory=lambda: os.getenv("TARGET_ACCESS_LOG_PATH", ""))
    target_error_log_path: str = field(default_factory=lambda: os.getenv("TARGET_ERROR_LOG_PATH", ""))
    target_log_format: str = field(default_factory=lambda: os.getenv("TARGET_LOG_FORMAT", "combined"))

    # Honeypot
    honeypot_enabled: bool = field(default_factory=lambda: _get_bool("HONEYPOT_ENABLED", False))
    honeypot_port: int = field(default_factory=lambda: _get_int("HONEYPOT_PORT", 8081))

    # Enforcement safety
    enforcement_allowlist: tuple = field(default_factory=lambda: _parse_allowlist(os.getenv("ENFORCEMENT_ALLOWLIST", "")))
    default_block_minutes: int = field(default_factory=lambda: _get_int("DEFAULT_BLOCK_MINUTES", 30))

    # Detection thresholds
    rate_window_seconds: int = field(default_factory=lambda: _get_int("RATE_WINDOW_SECONDS", 60))
    rate_threshold: int = field(default_factory=lambda: _get_int("RATE_THRESHOLD", 60))
    failed_login_window_seconds: int = field(default_factory=lambda: _get_int("FAILED_LOGIN_WINDOW_SECONDS", 300))
    failed_login_threshold: int = field(default_factory=lambda: _get_int("FAILED_LOGIN_THRESHOLD", 5))
    repeat_404_window_seconds: int = field(default_factory=lambda: _get_int("REPEAT_404_WINDOW_SECONDS", 120))
    repeat_404_threshold: int = field(default_factory=lambda: _get_int("REPEAT_404_THRESHOLD", 10))
    repeat_offender_rule_count: int = field(default_factory=lambda: _get_int("REPEAT_OFFENDER_RULE_COUNT", 3))
    repeat_offender_window_seconds: int = field(default_factory=lambda: _get_int("REPEAT_OFFENDER_WINDOW_SECONDS", 600))

    # Audit
    audit_log_path: str = field(default_factory=lambda: os.getenv("AIPS_AUDIT_LOG_PATH", "./data/audit.log"))

    def validate(self) -> list[str]:
        """Returns a list of human-readable problems. Empty list == OK to start."""
        problems = []
        if self.mode not in ("monitor", "enforcement"):
            problems.append(f"AIPS_MODE must be 'monitor' or 'enforcement', got '{self.mode}'")
        if self.host not in ("127.0.0.1", "localhost"):
            problems.append(
                f"AIPS_HOST='{self.host}' — the management dashboard must bind to 127.0.0.1 "
                "unless you have explicitly and knowingly chosen to expose it. Refusing to start "
                "with a non-loopback host by default."
            )
        if self.ai_enabled and not self.openrouter_api_key:
            problems.append(
                "AI_ENABLED=true but OPENROUTER_API_KEY is empty. Either set the key in .env or "
                "set AI_ENABLED=false. The rule-based detector works either way."
            )
        if self.target_log_format not in ("combined", "common", "unknown"):
            problems.append(f"TARGET_LOG_FORMAT must be combined|common|unknown, got '{self.target_log_format}'")
        return problems


config = Config()


def require_valid_config() -> Config:
    problems = config.validate()
    if problems:
        print("AIPS refused to start due to configuration problems:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nFix these in your .env file (see .env.example) and try again.", file=sys.stderr)
        sys.exit(1)
    return config
