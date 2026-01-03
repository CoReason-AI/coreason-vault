# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from unittest.mock import Mock, patch

import pytest
import requests
from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, VaultConnectionError


class TestAdditionalEdgeCases:
    """
    New test cases to cover gaps identified during review.
    """

    def test_auth_with_namespace(self) -> None:
        """Verify that VAULT_NAMESPACE is correctly passed to hvac Client."""
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_NAMESPACE="my-namespace",
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
        )
        auth = VaultAuthentication(config)

        with patch("coreason_vault.auth.hvac.Client") as MockClient:
            mock_instance = Mock()
            MockClient.return_value = mock_instance
            mock_instance.is_authenticated.return_value = True

            auth.get_client()

            MockClient.assert_called_once()
            _, kwargs = MockClient.call_args
            assert kwargs.get("namespace") == "my-namespace"

    def test_auth_ssl_verify_false(self) -> None:
        """Verify that VAULT_VERIFY_SSL=False is respected."""
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_VERIFY_SSL=False,
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
        )
        auth = VaultAuthentication(config)

        with patch("coreason_vault.auth.hvac.Client") as MockClient:
            mock_instance = Mock()
            MockClient.return_value = mock_instance
            mock_instance.is_authenticated.return_value = True

            auth.get_client()

            MockClient.assert_called_once()
            _, kwargs = MockClient.call_args
            assert kwargs.get("verify") is False

    def test_cipher_context_as_bytes_error(self) -> None:
        """
        Verify behavior when context is passed as bytes (should probably fail gracefully or raise TypeError).
        Since our type hint says Optional[str], this checks runtime resilience against bad input.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = VaultAuthentication(config)
        cipher = TransitCipher(auth)

        # Mock client not needed if it fails before call, but setup just in case
        auth.get_client = Mock()  # type: ignore

        # The code does: context.encode("utf-8")
        # If context is bytes, .encode() will fail (AttributeError: 'bytes' object has no attribute 'encode')
        # unless it's Python 2 (it's not).
        # We expect a standard Python exception, validating that we don't silently ignore it.
        with pytest.raises(AttributeError):
            cipher.encrypt("data", "key", context=b"bytes_context")  # type: ignore

    def test_auth_connection_error_generic(self) -> None:
        """
        Test generic connection error (e.g. ConnectionRefused) during auth,
        ensuring it maps to VaultConnectionError.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        with patch("coreason_vault.auth.hvac.Client") as MockClient:
            mock_instance = MockClient.return_value
            # requests.exceptions.ConnectionError
            mock_instance.auth.approle.login.side_effect = requests.exceptions.ConnectionError("Refused")

            with pytest.raises(VaultConnectionError) as exc:
                auth.get_client()
            assert "Vault authentication failed" in str(exc.value)

    def test_cipher_encrypt_none_plaintext(self) -> None:
        """Verify behavior when plaintext is None (should fail or be handled)."""
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = VaultAuthentication(config)
        cipher = TransitCipher(auth)
        auth.get_client = Mock()  # type: ignore

        # Code does plaintext.encode() or uses it as bytes. None fails.
        # It falls through to bytes handling and b64encode(None) raises TypeError.
        with pytest.raises(TypeError):
            cipher.encrypt(None, "key")  # type: ignore

    def test_decrypt_invalid_base64_padding(self) -> None:
        """Verify explicit base64 error handling in decrypt."""
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = VaultAuthentication(config)
        cipher = TransitCipher(auth)

        mock_client = Mock()
        auth.get_client = Mock(return_value=mock_client)  # type: ignore

        # Return invalid base64 (bad padding or chars)
        mock_client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": "InvalidB64!!"}}

        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("ct", "key")
        assert "Decryption failed" in str(exc.value)
