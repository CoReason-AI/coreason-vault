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
import threading
import time
from typing import Any
from unittest.mock import Mock, patch

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, VaultConnectionError
from coreason_vault.keeper import SecretKeeper


# --- Fixtures ---
@pytest.fixture  # type: ignore[misc]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


# --- SecretKeeper Edge Cases ---


def test_keeper_empty_secret(mock_auth: Any) -> None:
    """Test retrieving a secret that exists but is empty."""
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    # Empty dictionary
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}
    assert keeper.get_secret("empty/path") == {}


def test_keeper_custom_mount(mock_auth: Any) -> None:
    """Test retrieving secret from a custom mount point."""
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_MOUNT_POINT="custom-mount")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"foo": "bar"}}}
    keeper.get_secret("path")

    client.secrets.kv.v2.read_secret_version.assert_called_with(path="path", mount_point="custom-mount")


# --- TransitCipher Edge Cases ---


def test_cipher_unicode_torture(mock_auth: Any) -> None:
    """Test encryption and decryption of complex unicode strings."""
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    unicode_str = "🔒 Secrèt 🚀 € @ ß"
    b64_str = base64.b64encode(unicode_str.encode("utf-8")).decode("utf-8")

    # Mock Encrypt
    client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:unicode"}}
    assert cipher.encrypt(unicode_str, "key") == "vault:v1:unicode"

    # Check what was sent
    client.secrets.transit.encrypt_data.assert_called_with(name="key", plaintext=b64_str, context=None)

    # Mock Decrypt
    client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": b64_str}}
    assert cipher.decrypt("vault:v1:unicode", "key") == unicode_str


def test_cipher_malformed_base64_response(mock_auth: Any) -> None:
    """Test behavior when Vault returns invalid base64 (should raise EncryptionError)."""
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    # Invalid base64 in response
    client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": "!!!NOT-BASE64!!!"}}

    with pytest.raises(EncryptionError) as exc:
        cipher.decrypt("ciphertext", "key")

    # The underlying error (binascii.Error or similar) should be wrapped or caught
    assert "Decryption failed" in str(exc.value)


def test_cipher_vault_error(mock_auth: Any) -> None:
    """Test generic Vault error handling in cipher."""
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    client.secrets.transit.encrypt_data.side_effect = hvac.exceptions.VaultError("Server Error")

    with pytest.raises(EncryptionError):
        cipher.encrypt("data", "key")


# --- Concurrency & Threading ---


def test_concurrency_locking() -> None:
    """
    Simulate multiple threads trying to authenticate at once.
    Only one should trigger the login, others should wait and use the result.
    """
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
    auth = VaultAuthentication(config)

    # We need to mock hvac.Client to succeed
    with patch("coreason_vault.auth.hvac.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.is_authenticated.return_value = True

        # We also need to patch the _authenticate method on the INSTANCE to verify call count
        # But _authenticate calls hvac.Client, so we must be careful not to mock it out completely
        # unless we reproduce the side effect.
        # Easier strategy: Use the MockClient as the spy.

        # But wait, auth._authenticate() constructs hvac.Client().
        # So counting calls to MockClient() is sufficient to see how many times we tried to connect.

        # However, to simulate the RACE condition, we need the first call to block slightly.

        def slow_init(*args: Any, **kwargs: Any) -> Any:
            time.sleep(0.1)  # slow down init
            return client_instance

        MockClient.side_effect = slow_init

        # Threads
        threads = []
        results = []

        def worker() -> None:
            c = auth.get_client()
            results.append(c)

        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Assertions
        assert len(results) == 5
        # They should all be the same client object
        assert all(c == results[0] for c in results)

        # hvac.Client() should have been instantiated exactly once
        # (Assuming the lock works. If it didn't, we'd see 5 calls)
        assert MockClient.call_count == 1


# --- Network/Connection Edge Cases ---


def test_auth_network_timeout() -> None:
    """Test that connection timeouts (requests exceptions) are wrapped."""
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
    auth = VaultAuthentication(config)

    with patch("coreason_vault.auth.hvac.Client") as MockClient:
        # Simulate exception during Init
        MockClient.side_effect = requests.exceptions.ConnectTimeout("Timeout")

        with pytest.raises(VaultConnectionError) as exc:
            auth.get_client()

        assert "Vault authentication failed" in str(exc.value)
