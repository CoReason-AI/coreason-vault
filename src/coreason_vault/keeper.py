# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import threading
from typing import Any, Dict

import hvac
from cachetools import TTLCache

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError
from coreason_vault.utils.logger import logger


class SecretKeeper:
    """
    Manages secret retrieval from Vault's KV Version 2 engine.
    Implements caching using TTLCache to reduce load on Vault.
    Thread-safe to prevent cache stampedes.
    """

    def __init__(self, auth: VaultAuthentication, config: CoreasonVaultConfig):
        self.auth = auth
        self.config = config
        # Cache holding up to 1024 secrets for 60 seconds
        self._cache: TTLCache[str, Dict[str, Any]] = TTLCache(maxsize=1024, ttl=60)
        self._lock = threading.Lock()

    def get_secret(self, path: str) -> Dict[str, Any]:
        """
        Retrieves a secret from Vault.
        Checks local cache first.
        Uses locking to ensure thread-safety with TTLCache (which mutates on access).
        """
        with self._lock:
            # Check cache inside lock
            if path in self._cache:
                logger.debug(f"Secret {path} fetched from cache")
                return self._cache[path]

            # Fetch from Vault
            client = self.auth.get_client()
            mount_point = self.config.VAULT_MOUNT_POINT

            try:
                # Assume path does not contain mount point if mount_point is configured separately
                response = client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=mount_point,
                )

                secret_data = response["data"]["data"]

                # Update cache
                self._cache[path] = secret_data

                logger.info(f"Secret {path} fetched from Vault (cached: False)")
                return secret_data  # type: ignore[no-any-return]

            except hvac.exceptions.InvalidPath as e:
                logger.error(f"Secret not found at path: {path}")
                raise SecretNotFoundError(f"Secret not found: {path}") from e
            except hvac.exceptions.Forbidden as e:
                logger.error(f"Permission denied for secret path: {path}")
                raise PermissionError(f"Permission denied: {path}") from e
            except Exception:
                logger.exception(f"Error fetching secret {path}")
                raise

    # Alias for convenience and to match spec usage
    get = get_secret
