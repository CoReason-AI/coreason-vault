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
from datetime import datetime, timedelta
from typing import Any, Dict

import hvac

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError
from coreason_vault.utils.logger import logger


class SecretKeeper:
    """
    Manages secret retrieval from Vault's KV Version 2 engine.
    Implements caching to reduce load on Vault.
    Thread-safe to prevent cache stampedes.
    """

    def __init__(self, auth: VaultAuthentication, config: CoreasonVaultConfig):
        self.auth = auth
        self.config = config
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_expiry: Dict[str, datetime] = {}
        self.cache_ttl = 60  # seconds
        self._lock = threading.Lock()

    def get_secret(self, path: str) -> Dict[str, Any]:
        """
        Retrieves a secret from Vault.
        Checks local cache first.
        """
        # Single lock block for simplicity and correctness.
        # This prevents stampedes by blocking other threads while one fetches.
        # It also simplifies coverage as there are no race condition branches to test.
        with self._lock:
            # Check cache
            if path in self._cache and path in self._cache_expiry:
                if datetime.now() < self._cache_expiry[path]:
                    logger.debug(f"Secret {path} fetched from cache")
                    return self._cache[path]
                else:
                    logger.debug(f"Cache expired for {path}")
                    del self._cache[path]
                    del self._cache_expiry[path]

            # Fetch
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
                self._cache_expiry[path] = datetime.now() + timedelta(seconds=self.cache_ttl)

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
