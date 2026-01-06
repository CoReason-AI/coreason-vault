# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import base64
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, VaultConnectionError
from coreason_vault.keeper import SecretKeeper
from coreason_vault.manager import VaultManager


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    return auth, client


class TestComplexCipher:
    def test_context_mismatch_raises_encryption_error(self, mock_auth: Any) -> None:
        """
        Tests that if Vault rejects decryption (due to bad context),
        we raise EncryptionError.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Mock Vault returning an error for decryption
        client.secrets.transit.decrypt_data.side_effect = hvac.exceptions.InvalidRequest("Context mismatch")

        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("vault:v1:ciphertext", "my-key", context="wrong-context")

        assert "Decryption failed" in str(exc.value)

    def test_binary_data_handling(self, mock_auth: Any) -> None:
        """
        Tests that binary data (which cannot be utf-8 decoded) is returned as bytes.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Non-utf8 bytes
        binary_data = b"\x80\xff\x00\x12"
        encoded_b64 = base64.b64encode(binary_data).decode("utf-8")

        # Mock response from Vault (it always returns base64)
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_b64}}

        result = cipher.decrypt("vault:v1:binary", "my-key")
        assert isinstance(result, bytes)
        assert result == binary_data

    def test_large_payload_handling(self, mock_auth: Any) -> None:
        """
        Tests handling of a relatively large payload (e.g. 1MB).
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        large_string = "A" * 1024 * 1024  # 1MB
        encoded_b64 = base64.b64encode(large_string.encode("utf-8")).decode("utf-8")

        # Mock encrypt
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:large"}}
        # Mock decrypt
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_b64}}

        # Round trip
        ct = cipher.encrypt(large_string, "large-key")
        assert ct == "vault:v1:large"

        pt = cipher.decrypt(ct, "large-key")
        assert pt == large_string


class TestComplexKeeper:
    def test_deep_nested_secret(self, mock_auth: Any) -> None:
        """
        Verifies that SecretKeeper can handle and return deeply nested dictionaries.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        nested_data = {
            "level1": {
                "level2": {
                    "level3": "secret-value",
                    "list": [1, 2, 3],
                }
            }
        }

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": nested_data}}

        result = keeper.get_secret("nested/path")
        assert result == nested_data
        assert result["level1"]["level2"]["level3"] == "secret-value"

    def test_unexpected_vault_response_structure(self, mock_auth: Any) -> None:
        """
        If Vault returns a structure that isn't a dict in data['data'],
        SecretKeeper should raise ValueError (from existing code).
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Vault returns a list instead of a dict for the data payload
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": ["not", "a", "dict"]}}

        with pytest.raises(ValueError) as exc:
            keeper.get_secret("weird/path")
        assert "Expected dict from Vault" in str(exc.value)


class TestAuthNetworkFailures:
    @patch("time.sleep", return_value=None)  # Speed up retries
    def test_auth_exhausted_retries(self, mock_sleep: Mock) -> None:
        """
        Verify that VaultAuthentication raises VaultConnectionError after exhausting retries.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        # We need to mock hvac.Client construction to fail repeatedly
        with patch("hvac.Client", side_effect=requests.exceptions.ConnectionError("Connection refused")) as mock_hvac:
            with pytest.raises(VaultConnectionError) as exc:
                auth.get_client()

            assert mock_hvac.call_count == 3  # stop_after_attempt(3)
            assert "Vault authentication failed" in str(exc.value)

    @patch("time.sleep", return_value=None)
    def test_auth_token_renewal_failure(self, mock_sleep: Mock) -> None:
        """
        Verify that if token renewal fails (lookup_self fails AND re-auth fails),
        we raise VaultConnectionError.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        # 1. Setup initial state with a mocked client
        mock_client = MagicMock(spec=hvac.Client)
        auth._client = mock_client

        # 2. lookup_self raises Forbidden (token expired)
        mock_client.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("Expired")

        # 3. Re-authentication fails repeatedly (network error)
        # We need to mock _authenticate since it's the method called on failure
        # But wait, _authenticate is decorated with retry.
        # If we mock it directly, we bypass the retry logic unless we mock the underlying call inside it.
        # Let's mock hvac.Client constructor again to simulate re-auth failure.
        with patch("hvac.Client", side_effect=hvac.exceptions.VaultDown("Down")):
            with pytest.raises(VaultConnectionError) as exc:
                auth.get_client()

            assert "Vault re-authentication failed" in str(exc.value)


class TestConcurrencySimulation:
    def test_simulated_cache_race(self, mock_auth: Any) -> None:
        """
        Simulate a race condition where multiple threads might miss cache.
        We can't easily do real threads in a unit test deterministically,
        but we can verify that the lock is acquired.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock the fetch
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

        # Spy on the lock
        keeper._lock = MagicMock()
        keeper._lock.__enter__.return_value = None

        keeper.get_secret("path")

        # Verify lock was used
        keeper._lock.__enter__.assert_called_once()
        # Verify fetch occurred
        client.secrets.kv.v2.read_secret_version.assert_called_once()


class TestManagerIntegration:
    def test_manager_full_initialization(self) -> None:
        """
        Test that VaultManager correctly initializes all subcomponents
        with the same auth instance.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        manager = VaultManager(config)

        assert isinstance(manager.auth, VaultAuthentication)
        assert isinstance(manager.secrets, SecretKeeper)
        assert isinstance(manager.cipher, TransitCipher)

        # Verify they share the auth instance
        assert manager.secrets.auth is manager.auth
        assert manager.cipher.auth is manager.auth
