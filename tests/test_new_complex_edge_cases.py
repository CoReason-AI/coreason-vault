# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Any
from unittest.mock import Mock, patch

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    return auth, client


class TestNewComplexEdgeCases:
    def test_namespace_verification(self) -> None:
        """
        Verify that VAULT_NAMESPACE is correctly passed to the hvac.Client constructor.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
            VAULT_NAMESPACE="my-namespace",
        )
        auth = VaultAuthentication(config)

        with patch("hvac.Client") as MockClient:
            instance = MockClient.return_value
            instance.is_authenticated.return_value = True

            auth.get_client()

            MockClient.assert_called_with(url="http://localhost:8200/", namespace="my-namespace", verify=True)

    def test_read_timeout_handling_in_keeper(self, mock_auth: Any) -> None:
        """
        Explicitly verify that requests.exceptions.ReadTimeout (a subclass of RequestException)
        triggers the retry logic and eventually raises VaultConnectionError.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Simulate ReadTimeout for all retries
        client.secrets.kv.v2.read_secret_version.side_effect = requests.exceptions.ReadTimeout("Read timed out")

        with pytest.raises(VaultConnectionError) as exc:
            keeper.get_secret("timeout/path")

        assert "Failed to fetch secret after retries" in str(exc.value)
        # Should have retried 3 times
        assert client.secrets.kv.v2.read_secret_version.call_count == 3

    def test_large_secret_fetch(self, mock_auth: Any) -> None:
        """
        Test retrieving a secret with a very large payload to ensure no buffer overflows or crashes.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # 1MB string
        large_value = "X" * 1024 * 1024
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"large_key": large_value}}}

        result = keeper.get_secret("large/secret")
        assert result["large_key"] == large_value
        assert len(result["large_key"]) == 1024 * 1024

    def test_secret_with_empty_keys_and_values(self, mock_auth: Any) -> None:
        """
        Verify handling of secrets with empty strings as keys or values, and None values.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        complex_data = {"": "empty_key", "empty_val": "", "none_val": None, " ": "space_key"}

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": complex_data}}

        result = keeper.get_secret("complex/empty")
        assert result == complex_data
        assert result[""] == "empty_key"
        assert result["empty_val"] == ""
        assert result["none_val"] is None

    def test_keeper_get_alias(self, mock_auth: Any) -> None:
        """
        Verify that .get() is an alias for .get_secret() and works identically.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

        # Call alias
        result = keeper.get("alias/path")
        assert result == {"k": "v"}
        client.secrets.kv.v2.read_secret_version.assert_called_with(path="alias/path", mount_point="secret")

    def test_token_validation_boundary_conditions(self) -> None:
        """
        Verify _should_validate_token logic with precise boundary checks.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret", VAULT_TOKEN_TTL=60
        )
        auth = VaultAuthentication(config)

        # 1. Initially (last_check = 0), it should validate
        assert auth._should_validate_token() is True

        # 2. Just checked (time now = 100, last check = 100) -> False
        with patch("time.time", return_value=100.0):
            auth._last_token_check = 100.0
            assert auth._should_validate_token() is False

        # 3. 59 seconds later (time now = 159) -> False
        with patch("time.time", return_value=159.0):
            auth._last_token_check = 100.0
            assert auth._should_validate_token() is False

        # 4. 61 seconds later (time now = 161) -> True
        with patch("time.time", return_value=161.0):
            auth._last_token_check = 100.0
            assert auth._should_validate_token() is True

    def test_verify_ssl_config_propagation(self) -> None:
        """
        Verify VAULT_VERIFY_SSL=False is propagated to hvac.Client.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret", VAULT_VERIFY_SSL=False
        )
        auth = VaultAuthentication(config)

        with patch("hvac.Client") as MockClient:
            instance = MockClient.return_value
            instance.is_authenticated.return_value = True

            auth.get_client()

            MockClient.assert_called_with(url="http://localhost:8200/", namespace=None, verify=False)
