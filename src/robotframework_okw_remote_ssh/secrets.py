from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml


def default_secrets_path() -> str:
    # Windows: %USERPROFILE%\.okw\secrets.yaml
    # Linux/macOS: ~/.okw/secrets.yaml
    home = Path.home()
    return str(home / ".okw" / "secrets.yaml")


class SecretStore:
    """
    Loads secrets from a local YAML file outside the repository.
    MUST NOT log or expose secret values.
    """

    def __init__(self, secrets_path: str | None = None):
        self._path = secrets_path or default_secrets_path()
        self._cache: Dict[str, Any] | None = None

    def _load(self) -> Dict[str, Any]:
        if self._cache is not None:
            return self._cache

        if not os.path.exists(self._path):
            raise RuntimeError(f"Secrets file not found: {self._path}")

        with open(self._path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        secrets = data.get("secrets")
        if not isinstance(secrets, dict):
            raise RuntimeError("Invalid secrets file: missing top-level 'secrets' mapping.")

        self._cache = secrets
        return secrets

    def get_password(self, secret_id: str) -> str:
        secrets = self._load()
        entry = secrets.get(secret_id)

        if not isinstance(entry, dict):
            raise RuntimeError(f"Secret not found: {secret_id}")

        pw = entry.get("password")
        if not pw:
            raise RuntimeError(f"Secret '{secret_id}' has no 'password' field.")

        # IMPORTANT: never log pw
        return str(pw)
