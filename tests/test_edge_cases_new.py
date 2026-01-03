# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Tuple
from unittest.mock import Mock, patch

import pytest
import requests
from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, VaultConnectionError
from coreason_vault.keeper import SecretKeeper
from hvac import exceptions


# Fixtures
@pytest.fixture  # type: ignore[misc, unused-ignore]
def mock_auth() -> Tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


class TestEdgeCasesNew:
    """
    Additional edge cases and robust failure mode testing.
    """

    def test_network_timeout_during_encryption(self, mock_auth: Tuple[Mock, Mock]) -> None:
        """
        Verify that a network timeout (requests.exceptions.Timeout) during encryption
        is wrapped into an EncryptionError (or bubbles up appropriately).
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Simulate network timeout
        client.secrets.transit.encrypt_data.side_effect = requests.exceptions.Timeout("Connection timed out")

        with pytest.raises(EncryptionError) as exc:
            cipher.encrypt("data", "key")

        assert "Connection timed out" in str(exc.value) or "Encryption failed" in str(exc.value)

    def test_invalid_ciphertext_format(self, mock_auth: Tuple[Mock, Mock]) -> None:
        """
        Verify decryption fails gracefully when passed garbage that isn't valid Vault ciphertext.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # hvac might raise an InvalidRequest or similar if the format is wrong,
        # or the server returns 400.
        client.secrets.transit.decrypt_data.side_effect = exceptions.InvalidRequest("Invalid ciphertext")

        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("garbage_string", "key")

        assert "Decryption failed" in str(exc.value)

    def test_large_payload_encryption(self, mock_auth: Tuple[Mock, Mock]) -> None:
        """
        Verify handling of a large payload (e.g. 10MB).
        In a mock, we just ensure it passes the large string to the client.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        large_payload = "A" * (10 * 1024 * 1024)  # 10MB
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:..."}}

        cipher.encrypt(large_payload, "key")

        # Verify call was made with the massive base64 string
        # We don't want to print the arg in failure message if it fails, but check it was called.
        assert client.secrets.transit.encrypt_data.called
        # Check size of passed plaintext
        call_args = client.secrets.transit.encrypt_data.call_args
        # plaintext arg is base64 encoded
        encoded_arg = call_args[1]["plaintext"]
        assert len(encoded_arg) > len(large_payload)

    def test_secret_keeper_permission_denied_specific(self, mock_auth: Tuple[Mock, Mock]) -> None:
        """
        Verify specific PermissionError when accessing a restricted secret.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.secrets.kv.v2.read_secret_version.side_effect = exceptions.Forbidden("Permission denied")

        with pytest.raises(PermissionError):
            keeper.get_secret("restricted/secret")

    def test_auth_connection_timeout(self) -> None:
        """
        Verify that if the initial auth connection times out, it raises VaultConnectionError.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        with patch("hvac.Client") as MockClient:
            # Simulate timeout during login
            instance = MockClient.return_value
            instance.auth.approle.login.side_effect = requests.exceptions.Timeout("Connect timeout")

            with pytest.raises(VaultConnectionError) as exc:
                auth.get_client()

            assert "Vault authentication failed" in str(exc.value)

    def test_decrypt_non_base64_response(self, mock_auth: Tuple[Mock, Mock]) -> None:
        """
        Verify behavior if Vault returns a plaintext that is NOT valid base64
        (should not happen in Transit, but defensive check).
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Vault transit decrypt returns base64 of original plaintext.
        # If it returns "hello", that's not valid base64 for "hello".
        # Wait, "hello" IS valid base64? No.
        # "AAAA" is valid. "!!!!" is not.

        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": "!!!!"}}

        # binascii.Error is raised by b64decode
        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("ct", "key")

        assert "Decryption failed" in str(exc.value)
