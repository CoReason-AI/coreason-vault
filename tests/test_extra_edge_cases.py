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
from typing import Any, Generator, Tuple
from unittest.mock import Mock

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> Generator[Tuple[Mock, Mock], None, None]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    yield auth, client


class TestExtraEdgeCases:
    def test_encrypt_decrypt_empty_string(self, mock_auth: Any) -> None:
        """
        Verify that empty strings can be encrypted and decrypted.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Encrypt empty string
        # Base64 of "" is ""
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:empty"}}
        ct = cipher.encrypt("", "key")
        assert ct == "vault:v1:empty"
        # Check that empty string was sent as plaintext (Base64 encoded empty is empty)
        client.secrets.transit.encrypt_data.assert_called_with(name="key", plaintext="", context=None)

        # Decrypt to empty string
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": ""}}
        pt = cipher.decrypt("vault:v1:empty", "key")
        assert pt == ""

    def test_decrypt_invalid_base64_response_from_vault(self, mock_auth: Any) -> None:
        """
        If Vault returns something that isn't valid Base64 in 'plaintext',
        decrypt should raise an error (likely binascii.Error), which should be caught/wrapped?
        Or maybe it propagates? The code does base64.b64decode(encoded_plaintext, validate=True).
        If that fails, it raises binascii.Error.
        The implementation catches Exception and wraps in EncryptionError.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Vault returns invalid base64
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": "!!!invalid_base64!!!"}}

        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("ciphertext", "key")

        assert "Decryption failed" in str(exc.value)

    def test_malformed_vault_response_kv(self, mock_auth: Any) -> None:
        """
        Verify behavior when Vault returns JSON that doesn't match KV v2 structure.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Missing 'data' key entirely
        client.secrets.kv.v2.read_secret_version.return_value = {"something": "else"}

        with pytest.raises(KeyError):
            # The code does response["data"]["data"]
            # If "data" is missing, KeyError raises.
            # Implementation catches generic Exception and logs it, then re-raises.
            keeper.get_secret("path")

    def test_malformed_vault_response_kv_inner_data(self, mock_auth: Any) -> None:
        """
        Verify behavior when Vault returns 'data' but inner 'data' is missing/wrong.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Missing inner 'data'
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"metadata": {}}}

        with pytest.raises(KeyError):
            keeper.get_secret("path")

    def test_malformed_vault_response_kv_not_dict(self, mock_auth: Any) -> None:
        """
        Verify behavior when inner data is not a dict (e.g. string or list).
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Inner 'data' is a list
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": ["not", "a", "dict"]}}

        with pytest.raises(ValueError) as exc:
            keeper.get_secret("path")

        assert "Expected dict from Vault" in str(exc.value)

    def test_binary_data_encryption(self, mock_auth: Any) -> None:
        """
        Verify that raw binary bytes are correctly base64 encoded before sending.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        binary_data = b"\x00\xff\x10\x20"
        expected_b64 = base64.b64encode(binary_data).decode("utf-8")

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:bin"}}

        cipher.encrypt(binary_data, "key")

        client.secrets.transit.encrypt_data.assert_called_with(name="key", plaintext=expected_b64, context=None)

    def test_lookup_self_returns_malformed_data(self) -> None:
        """
        Verify Auth behavior when lookup_self returns unexpected structure.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
            VAULT_TOKEN_TTL=0,  # Force validation
        )
        auth = VaultAuthentication(config)

        # Inject a client
        mock_client = Mock(spec=hvac.Client)
        auth._client = mock_client

        # lookup_self returns success but missing ttl
        mock_client.auth.token.lookup_self.return_value = {"data": {}}  # No 'ttl'

        # Implementation: ttl = response.get("data", {}).get("ttl", 0)
        # So it defaults to 0.
        # If ttl < 10, it raises Forbidden("Token expiring soon").
        # So this should trigger re-authentication.

        # Mock re-authentication logic
        mock_client.login = Mock()  # doesn't matter, we mock _authenticate method usually or class

        # But wait, Auth calls `self._authenticate()` if Forbidden is raised.
        # We need to mock `_authenticate` to avoid actual network call and to verify it was called.

        auth._authenticate = Mock(return_value=mock_client)

        auth.get_client()

        # It should have called _authenticate because ttl defaulted to 0
        auth._authenticate.assert_called()

    def test_token_validation_handles_random_exception(self) -> None:
        """
        Verify that random exceptions during token validation don't crash everything
        if they are not Forbidden/VaultError?
        The code catches (hvac.exceptions.Forbidden, hvac.exceptions.VaultError).
        If lookup_self raises ValueError (e.g. malformed json from library?), it propagates?
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_TOKEN_TTL=0)
        auth = VaultAuthentication(config)
        mock_client = Mock(spec=hvac.Client)
        auth._client = mock_client

        # Random exception
        mock_client.auth.token.lookup_self.side_effect = Exception("Boom")

        # Should propagate
        with pytest.raises(Exception) as exc:
            auth.get_client()
        assert "Boom" in str(exc.value)
