# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Any, Generator, Tuple
from unittest.mock import Mock

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError, VaultConnectionError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> Generator[Tuple[Mock, Mock], None, None]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    yield auth, client


class TestDynamicSecrets:
    def test_get_dynamic_secret_success(self, mock_auth: Any) -> None:
        """
        Verify that get_dynamic_secret calls client.read and returns full response.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock successful response for a dynamic secret (e.g., AWS)
        mock_response = {
            "lease_id": "aws/creds/role/123",
            "lease_duration": 3600,
            "data": {"access_key": "AKIA...", "secret_key": "secret..."},
        }
        client.read.return_value = mock_response

        result = keeper.get_dynamic_secret("aws/creds/my-role")

        assert result == mock_response
        client.read.assert_called_once_with("aws/creds/my-role")

    def test_get_dynamic_secret_not_found_none(self, mock_auth: Any) -> None:
        """
        Verify that if client.read returns None (typical for 404 in hvac),
        SecretNotFoundError is raised.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.read.return_value = None

        with pytest.raises(SecretNotFoundError) as exc:
            keeper.get_dynamic_secret("aws/creds/missing")

        assert "Dynamic secret not found" in str(exc.value)

    def test_get_dynamic_secret_network_error_retry(self, mock_auth: Any) -> None:
        """
        Verify that network errors trigger retries.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Raise exception
        client.read.side_effect = requests.exceptions.ConnectionError("Connection failed")

        with pytest.raises(VaultConnectionError) as exc:
            keeper.get_dynamic_secret("aws/creds/role")

        assert "Failed to fetch dynamic secret after retries" in str(exc.value)
        assert client.read.call_count >= 3

    def test_get_dynamic_secret_permission_denied(self, mock_auth: Any) -> None:
        """
        Verify permission denied handling.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.read.side_effect = hvac.exceptions.Forbidden("Forbidden")

        with pytest.raises(PermissionError) as exc:
            keeper.get_dynamic_secret("aws/creds/protected")

        assert "Permission denied" in str(exc.value)

    def test_get_dynamic_secret_malformed_response(self, mock_auth: Any) -> None:
        """
        Verify behavior when response is not a dict (unlikely from hvac, but good for defense).
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.read.return_value = "not-a-dict"

        with pytest.raises(ValueError) as exc:
            keeper.get_dynamic_secret("aws/creds/weird")

        assert "Expected dict" in str(exc.value)
