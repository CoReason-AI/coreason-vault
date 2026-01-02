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
from unittest.mock import MagicMock, Mock

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError


@pytest.fixture  # type: ignore[misc, unused-ignore]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock()
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


class TestTransitCipherComplex:
    def test_context_mismatch(self, mock_auth: Any) -> None:
        """
        Verify that decrypting with a different context than used for encryption
        raises an EncryptionError (simulating Vault's rejection or MAC failure).
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Mock encryption success
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:encrypted"}}

        # Encrypt with context A
        ciphertext = cipher.encrypt("secret", "my-key", context="user-A")
        assert ciphertext == "vault:v1:encrypted"

        # Mock decryption failure due to context mismatch
        # Vault raises hvac.exceptions.InvalidRequest or similar for bad context/MAC
        client.secrets.transit.decrypt_data.side_effect = hvac.exceptions.InvalidRequest(
            "ciphertext verification failed"
        )

        # Try decrypt with context B
        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt(ciphertext, "my-key", context="user-B")

        assert "Decryption failed" in str(exc.value)

    def test_binary_data_roundtrip(self, mock_auth: Any) -> None:
        """
        Verify that binary data (e.g. random bytes) is handled correctly.
        It should enter as bytes, be base64 encoded for Vault, and if it's not valid UTF-8,
        come out as bytes.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Random binary data (not valid utf-8)
        raw_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

        # Expected base64 sent to vault
        encoded_b64 = base64.b64encode(raw_data).decode("utf-8")

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:image_blob"}}

        # Mock decryption response (Vault returns the original base64)
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_b64}}

        # Encrypt
        ct = cipher.encrypt(raw_data, "img-key")

        # Decrypt
        pt = cipher.decrypt(ct, "img-key")

        # Should return bytes because it's not valid utf-8
        assert isinstance(pt, bytes)
        assert pt == raw_data

    def test_unicode_handling(self, mock_auth: Any) -> None:
        """Verify handling of complex Unicode characters."""
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        unicode_str = "🔒 Secret 🔑 with Emoji & Symbols ¥©®"

        encoded_b64 = base64.b64encode(unicode_str.encode("utf-8")).decode("utf-8")

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:unicode"}}
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_b64}}

        ct = cipher.encrypt(unicode_str, "unicode-key")
        pt = cipher.decrypt(ct, "unicode-key")

        assert isinstance(pt, str)
        assert pt == unicode_str

    def test_empty_input(self, mock_auth: Any) -> None:
        """Verify handling of empty strings."""
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        empty_str = ""
        encoded_empty = ""  # base64 of empty is empty

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:empty"}}
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_empty}}

        ct = cipher.encrypt(empty_str, "key")
        pt = cipher.decrypt(ct, "key")

        assert pt == ""


class TestAuthResilience:
    def test_token_auto_renewal_flow(self) -> None:
        """
        Test the logic in VaultAuthentication.get_client() where an expired token
        (detected via lookup_self failure) triggers a re-authentication.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")

        # We need to partial-mock VaultAuthentication to spy on _authenticate
        # and mock the hvac Client it produces.

        # Create instance
        auth = VaultAuthentication(config)

        # Create two mock clients:
        # 1. The stale client that fails lookup_self
        stale_client = MagicMock(spec=hvac.Client)
        # Raising Forbidden on lookup_self simulates expiry
        stale_client.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("Token expired")

        # 2. The fresh client returned by re-auth
        fresh_client = MagicMock(spec=hvac.Client)
        fresh_client.is_authenticated.return_value = True

        # Manually set the internal client to the stale one (simulate previous usage)
        auth._client = stale_client

        # Mock _authenticate to return the fresh client
        # We use patch.object on the instance method
        auth._authenticate = Mock(return_value=fresh_client)  # type: ignore

        # Action: Call get_client()
        result_client = auth.get_client()

        # Assertions
        # 1. It should have called lookup_self on the stale client
        stale_client.auth.token.lookup_self.assert_called_once()

        # 2. It should have caught the Forbidden error and called _authenticate
        auth._authenticate.assert_called_once()

        # 3. It should return the fresh client
        assert result_client == fresh_client

        # 4. The internal state should be updated
        assert auth._client == fresh_client
