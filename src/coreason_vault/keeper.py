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
import requests
from cachetools import TTLCache
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError, VaultConnectionError
from coreason_vault.utils.logger import logger

# Define retryable exceptions
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.RequestException,
    hvac.exceptions.VaultDown,
    hvac.exceptions.InternalServerError,
    hvac.exceptions.BadGateway,
)


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

            # Fetch from Vault (with retries handled by _fetch_from_vault)
            # Wrap in try/except to catch exhausted retries
            try:
                secret_data = self._fetch_from_vault(path)
            except RETRYABLE_EXCEPTIONS as e:
                # Catch network errors that exhausted retries
                logger.error(f"Failed to fetch secret {path} after retries: {e}")
                raise VaultConnectionError(f"Failed to fetch secret after retries: {e}") from e

            # Update cache
            self._cache[path] = secret_data

            logger.info(f"Secret {path} fetched from Vault (cached: False)")
        return secret_data  # type: ignore[no-any-return]

    @retry(  # type: ignore[misc]
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _fetch_from_vault(self, path: str) -> Dict[str, Any]:
        """
        Internal method to fetch from Vault with retries.
        """
        client = self.auth.get_client()
        mount_point = self.config.VAULT_MOUNT_POINT

        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount_point,
            )
            data = response["data"]["data"]
            if not isinstance(data, dict):
                raise ValueError(f"Expected dict from Vault, got {type(data)}")
            return data

        except hvac.exceptions.InvalidPath as e:
            logger.error(f"Secret not found at path: {path}")
            raise SecretNotFoundError(f"Secret not found: {path}") from e
        except hvac.exceptions.Forbidden as e:
            logger.error(f"Permission denied for secret path: {path}")
            raise PermissionError(f"Permission denied: {path}") from e
        except RETRYABLE_EXCEPTIONS:
            # Propagate for retry
            raise
        except Exception:
            logger.exception(f"Error fetching secret {path}")
            raise

    def get_dynamic_secret(self, path: str) -> Dict[str, Any]:
        """
        Retrieves a dynamic secret (e.g., AWS, Database creds) from Vault.
        Does NOT use the local cache to ensure freshness and respect lease duration.
        Returns the full response including lease_id and lease_duration.
        """
        try:
            return self._fetch_dynamic_secret(path)  # type: ignore[no-any-return]
        except RETRYABLE_EXCEPTIONS as e:
            logger.error(f"Failed to fetch dynamic secret {path} after retries: {e}")
            raise VaultConnectionError(f"Failed to fetch dynamic secret after retries: {e}") from e

    @retry(  # type: ignore[misc]
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _fetch_dynamic_secret(self, path: str) -> Dict[str, Any]:
        """
        Internal method to fetch dynamic secret with retries.
        """
        client = self.auth.get_client()

        try:
            # Use raw read for dynamic backends
            response = client.read(path)

            if response is None:
                # client.read returns None if path doesn't exist or is 404
                logger.error(f"Dynamic secret not found at path: {path}")
                raise SecretNotFoundError(f"Dynamic secret not found: {path}")

            # Dynamic secrets usually have 'data', 'lease_id', 'lease_duration' at top level
            # We return the whole response so consumer can see lease info.
            if not isinstance(response, dict):
                raise ValueError(f"Expected dict from Vault, got {type(response)}")

            logger.info(f"Dynamic secret {path} fetched from Vault")
            return response

        except hvac.exceptions.InvalidPath as e:
            logger.error(f"Dynamic secret path invalid: {path}")
            raise SecretNotFoundError(f"Secret not found: {path}") from e
        except hvac.exceptions.Forbidden as e:
            logger.error(f"Permission denied for dynamic secret path: {path}")
            raise PermissionError(f"Permission denied: {path}") from e
        except RETRYABLE_EXCEPTIONS:
            # Propagate
            raise
        except Exception:
            logger.exception(f"Error fetching dynamic secret {path}")
            raise

    # Alias for convenience and to match spec usage
    get = get_secret
