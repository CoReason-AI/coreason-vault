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
import time
from typing import Optional

import hvac
import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError
from coreason_vault.utils.logger import logger

# Define retryable exceptions
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.RequestException,
    hvac.exceptions.VaultDown,
    hvac.exceptions.InternalServerError,
    hvac.exceptions.BadGateway,
)


class VaultAuthentication:
    """
    Handles authentication with HashiCorp Vault.
    Supports AppRole and Kubernetes authentication methods.
    """

    def __init__(self, config: CoreasonVaultConfig):
        self.config = config
        self._client: Optional[hvac.Client] = None
        self._last_token_check: float = 0.0
        self._lock = threading.Lock()

    def get_client(self) -> hvac.Client:
        """
        Returns an authenticated Vault client.
        Checks token validity and renews/re-authenticates if necessary.
        Uses a short TTL to avoid checking on every call.
        Thread-safe to prevent concurrent re-authentication.
        """
        # First check (optimistic)
        if self._client is not None and not self._should_validate_token():
            return self._client

        with self._lock:
            # Double-check inside lock
            if self._client is not None and not self._should_validate_token():
                return self._client

            if self._client is None:
                try:
                    self._client = self._authenticate()
                except ValueError:
                    # Configuration errors should propagate immediately
                    raise
                except Exception as e:
                    # Wrap errors from initial auth
                    if isinstance(e, VaultConnectionError):
                        raise
                    logger.error(f"Authentication failed after retries: {e}")
                    raise VaultConnectionError(f"Vault authentication failed: {e}") from e
                return self._client

            # Must validate
            try:
                # Check if token is valid and active
                # lookup_self raises Forbidden if token is invalid/expired
                response = self._client.auth.token.lookup_self()

                # Check if token is expiring soon (grace period 10s)
                # response['data']['ttl'] is remaining seconds
                ttl = response.get("data", {}).get("ttl", 0)
                if ttl < 10:
                    logger.info(f"Vault token TTL ({ttl}s) too low, re-authenticating...")
                    raise hvac.exceptions.Forbidden("Token expiring soon")

                self._last_token_check = time.time()
            except (hvac.exceptions.Forbidden, hvac.exceptions.VaultError):
                logger.info("Vault token expired, invalid, or expiring soon, re-authenticating...")
                try:
                    self._client = self._authenticate()
                except Exception as e:
                    if isinstance(e, VaultConnectionError):
                        raise
                    logger.error(f"Re-authentication failed after retries: {e}")
                    raise VaultConnectionError(f"Vault re-authentication failed: {e}") from e

            return self._client

    def _should_validate_token(self) -> bool:
        """
        Determines if we should validate the token against the server.
        """
        return (time.time() - self._last_token_check) > self.config.VAULT_TOKEN_TTL

    @retry(  # type: ignore[misc]
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _authenticate(self) -> hvac.Client:
        """
        Authenticates to Vault using the configured method.
        Retries on transient network errors.
        """
        try:
            client = hvac.Client(
                url=str(self.config.VAULT_ADDR),
                namespace=self.config.VAULT_NAMESPACE,
                verify=self.config.VAULT_VERIFY_SSL,
            )

            if self.config.VAULT_ROLE_ID and self.config.VAULT_SECRET_ID:
                logger.info("Authenticating to Vault via AppRole")
                client.auth.approle.login(
                    role_id=self.config.VAULT_ROLE_ID,
                    secret_id=self.config.VAULT_SECRET_ID,
                )
            elif self.config.KUBERNETES_SERVICE_ACCOUNT_TOKEN:
                logger.info("Authenticating to Vault via Kubernetes")

                role = self.config.VAULT_K8S_ROLE
                if not role:
                    logger.error("Kubernetes authentication requires a role (set via VAULT_K8S_ROLE)")
                    raise ValueError("Missing Kubernetes role (VAULT_K8S_ROLE)")

                client.auth.kubernetes.login(
                    role=role,
                    jwt=self.config.KUBERNETES_SERVICE_ACCOUNT_TOKEN,
                )
            else:
                logger.error("No valid authentication method found in configuration")
                raise ValueError("Missing authentication credentials (AppRole or Kubernetes)")

            if not client.is_authenticated():
                logger.error("Client claims success but is_authenticated() is False")
                raise VaultConnectionError("Vault authentication failed silently")

            logger.info("Successfully authenticated to Vault")
            # Reset validation timer on fresh auth
            self._last_token_check = time.time()
            return client

        except ValueError:
            raise
        except RETRYABLE_EXCEPTIONS:
            # Let tenacity handle these
            raise
        except hvac.exceptions.VaultError as e:
            # Fatal Vault errors (like 400 Bad Request)
            logger.error(f"Failed to authenticate with Vault: {e}")
            raise VaultConnectionError(f"Vault authentication failed: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during Vault authentication: {e}")
            raise VaultConnectionError(f"Vault authentication failed: {e}") from e
