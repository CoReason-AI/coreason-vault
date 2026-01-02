# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Optional

import hvac

from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.utils.logger import logger


class VaultAuthentication:
    """
    Handles authentication with HashiCorp Vault.
    Supports AppRole and Kubernetes authentication methods.
    """

    def __init__(self, config: CoreasonVaultConfig):
        self.config = config
        self._client: Optional[hvac.Client] = None

    def get_client(self) -> hvac.Client:
        """
        Returns an authenticated Vault client.
        Checks token validity and renews/re-authenticates if necessary.
        """
        if self._client is None:
            self._client = self._authenticate()
            return self._client

        try:
            # Check if token is valid and active
            # lookup_self raises Forbidden if token is invalid/expired
            self._client.auth.token.lookup_self()
        except (hvac.exceptions.Forbidden, hvac.exceptions.VaultError):
            logger.info("Vault token expired or invalid, re-authenticating...")
            self._client = self._authenticate()

        return self._client

    def _authenticate(self) -> hvac.Client:
        """
        Authenticates to Vault using the configured method.
        """
        client = hvac.Client(
            url=self.config.VAULT_ADDR,
            namespace=self.config.VAULT_NAMESPACE,
            verify=self.config.VAULT_VERIFY_SSL,
        )

        try:
            if self.config.VAULT_ROLE_ID and self.config.VAULT_SECRET_ID:
                logger.info("Authenticating to Vault via AppRole")
                client.auth.approle.login(
                    role_id=self.config.VAULT_ROLE_ID,
                    secret_id=self.config.VAULT_SECRET_ID,
                )
            elif self.config.KUBERNETES_SERVICE_ACCOUNT_TOKEN:
                logger.info("Authenticating to Vault via Kubernetes")
                # Default role for K8s auth usually matches the service account or is configured.
                # We assume standard K8s auth flow using VAULT_ROLE_ID as the role name.
                # The prompt specifies inputs:
                # "VAULT_ROLE_ID, VAULT_SECRET_ID OR KUBERNETES_SERVICE_ACCOUNT_TOKEN".
                # We interpret this as VAULT_ROLE_ID serving as the role parameter for K8s too.

                role = self.config.VAULT_ROLE_ID
                if not role:
                    logger.error("Kubernetes authentication requires a role (set via VAULT_ROLE_ID)")
                    raise ValueError("Missing Kubernetes role (VAULT_ROLE_ID)")

                client.auth.kubernetes.login(
                    role=role,
                    jwt=self.config.KUBERNETES_SERVICE_ACCOUNT_TOKEN,
                )
            else:
                logger.error("No valid authentication method found in configuration")
                raise ValueError("Missing authentication credentials (AppRole or Kubernetes)")

        except hvac.exceptions.VaultError as e:
            logger.error(f"Failed to authenticate with Vault: {e}")
            raise ConnectionError(f"Vault authentication failed: {e}") from e
        except Exception:
            logger.exception("Unexpected error during Vault authentication")
            raise

        if not client.is_authenticated():
            logger.error("Client claims success but is_authenticated() is False")
            raise ConnectionError("Vault authentication failed silently")

        logger.info("Successfully authenticated to Vault")
        return client
