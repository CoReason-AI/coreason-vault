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
from unittest.mock import MagicMock, Mock, patch

import hvac
import pytest
from loguru import logger
from pydantic import ValidationError

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, SecretNotFoundError
from coreason_vault.keeper import SecretKeeper


class TestFinalEdgeCases:
    # --- Existing Tests (Preserved) ---
    def test_cipher_context_types(self) -> None:
        """
        Verify that passing invalid types to context raises TypeError.
        Requirement: Context must be str or bytes.
        """
        auth = Mock(spec=VaultAuthentication)
        # get_client must succeed before validation in _encrypt_impl
        auth.get_client.return_value = MagicMock()

        cipher = TransitCipher(auth)

        # Int context
        with pytest.raises(TypeError, match="Expected str or bytes"):
            cipher.encrypt("secret", "key", context=123)  # type: ignore[arg-type]

        # List context
        with pytest.raises(TypeError, match="Expected str or bytes"):
            cipher.encrypt("secret", "key", context=["bad"])  # type: ignore[arg-type]  # noqa: F821

    def test_non_dict_secret_payload(self) -> None:
        """
        Verify that if Vault returns a non-dict payload for a KV secret,
        SecretKeeper raises ValueError strictly.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Vault returns a list instead of a dict for 'data'
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": ["not", "a", "dict"]}}

        with pytest.raises(ValueError, match="Expected dict from Vault"):
            keeper.get_secret("path")

        # Vault returns a string
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": "just a string"}}
        with pytest.raises(ValueError, match="Expected dict from Vault"):
            keeper.get_secret("path")

    def test_large_payload_encryption(self) -> None:
        """
        Verify that the package can handle large payloads locally.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        cipher = TransitCipher(auth)

        # 1MB string
        large_payload = "a" * 1_000_000
        mock_ciphertext = "vault:v1:encrypted_blob"

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": mock_ciphertext}}

        ct = cipher.encrypt(large_payload, "key")
        assert ct == mock_ciphertext

        # Verify it was base64 encoded before sending
        call_args = client.secrets.transit.encrypt_data.call_args
        assert call_args is not None
        sent_plaintext = call_args[1]["plaintext"]
        assert len(sent_plaintext) > len(large_payload)

    def test_nested_secret_json(self) -> None:
        """
        Verify that deeply nested JSON is returned correctly.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        nested_data = {"level1": {"level2": {"level3": "secret_val", "list": [1, 2, 3]}}}
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": nested_data}}

        result = keeper.get_secret("nested/path")
        assert result == nested_data
        assert result["level1"]["level2"]["list"] == [1, 2, 3]

    def test_auth_method_priority(self) -> None:
        """
        Verify that if both AppRole and K8s vars are set, AppRole takes precedence.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_ROLE_ID="approle-id",
            VAULT_SECRET_ID="approle-secret",
            VAULT_K8S_ROLE="k8s-role",
            KUBERNETES_SERVICE_ACCOUNT_TOKEN="k8s-token",
        )
        auth = VaultAuthentication(config)

        with patch("hvac.Client") as MockClient:
            client_instance = MockClient.return_value
            client_instance.is_authenticated.return_value = True

            auth.get_client()

            client_instance.auth.approle.login.assert_called_once_with(role_id="approle-id", secret_id="approle-secret")
            client_instance.auth.kubernetes.login.assert_not_called()

    def test_auth_method_k8s_fallback(self) -> None:
        """
        Verify K8s is used if AppRole is missing.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_K8S_ROLE="k8s-role",
            KUBERNETES_SERVICE_ACCOUNT_TOKEN="k8s-token",
        )
        auth = VaultAuthentication(config)

        with patch("hvac.Client") as MockClient:
            client_instance = MockClient.return_value
            client_instance.is_authenticated.return_value = True

            auth.get_client()

            client_instance.auth.kubernetes.login.assert_called_once_with(role="k8s-role", jwt="k8s-token")
            client_instance.auth.approle.login.assert_not_called()

    def test_logging_security(self, caplog: pytest.LogCaptureFixture) -> None:
        """
        Verify that secrets are not logged during error conditions.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"api_key": "sk-12345"}}}

        handler_id = logger.add(caplog.handler, format="{message}")

        try:
            val = keeper.get_secret("safe/path")
            assert val["api_key"] == "sk-12345"

            assert "Secret safe/path fetched" in caplog.text
            assert "sk-12345" not in caplog.text

        finally:
            logger.remove(handler_id)

    # --- New Edge Case Tests ---

    def test_binary_data_transit(self) -> None:
        """
        Verify that TransitCipher handles raw binary data (bytes) correctly.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        cipher = TransitCipher(auth)

        # Raw bytes (e.g., an image header)
        binary_payload = b"\x89PNG\r\n\x1a\n\x00\x00"
        mock_ciphertext = "vault:v1:encrypted_png"

        # Mock encryption return
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": mock_ciphertext}}

        # Encrypt
        ct = cipher.encrypt(binary_payload, "key-images")
        assert ct == mock_ciphertext

        # Verify it was base64 encoded correctly before sending
        call_args = client.secrets.transit.encrypt_data.call_args
        sent_plaintext = call_args[1]["plaintext"]
        expected_b64 = base64.b64encode(binary_payload).decode("utf-8")
        assert sent_plaintext == expected_b64

        # Mock decryption return
        # Vault returns base64 of the plaintext
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": expected_b64}}

        # Decrypt
        pt = cipher.decrypt(mock_ciphertext, "key-images")
        # Should return bytes because it's not utf-8 decodeable (or valid utf-8 but we expect bytes?)
        # Wait, the implementation tries to decode utf-8. If it fails, it returns bytes.
        # \x89PNG... is definitely not valid UTF-8.
        assert isinstance(pt, bytes)
        assert pt == binary_payload

    def test_empty_inputs(self) -> None:
        """
        Verify behavior with empty inputs.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")

        # 1. Encrypt empty string
        cipher = TransitCipher(auth)
        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:empty"}}
        ct = cipher.encrypt("", "key")
        assert ct == "vault:v1:empty"
        # Verify base64 of empty string is empty string
        client.secrets.transit.encrypt_data.assert_called_with(name="key", plaintext="", context=None)

        # 2. Fetch empty path (should probably be handled by Vault as 404 or InvalidPath)
        keeper = SecretKeeper(auth, config)
        client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath("Missing path")

        with pytest.raises(SecretNotFoundError):
            keeper.get_secret("")

    def test_malicious_path_traversal(self) -> None:
        """
        Verify that path traversal attempts are passed to Vault (which handles them)
        or rejected if we had local validation (we don't, but Vault will reject or treat as literal).
        We mainly ensure it doesn't crash the client.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock Vault response for a weird path
        # Vault treats ../ literally or normalizes it. hvac passes it through.
        # We assume Vault handles security, but we verify our code doesn't choke.
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"pwned": False}}}

        val = keeper.get_secret("../../etc/passwd")
        assert val == {"pwned": False}
        client.secrets.kv.v2.read_secret_version.assert_called_with(path="../../etc/passwd", mount_point="secret")

    def test_config_edge_cases(self) -> None:
        """
        Verify configuration validation edge cases.
        """
        # 1. Invalid URL scheme
        with pytest.raises(ValidationError):
            CoreasonVaultConfig(VAULT_ADDR="ftp://invalid-scheme")

        # 2. Missing mandatory fields (VAULT_ADDR)
        with pytest.raises(ValidationError):
            CoreasonVaultConfig()

        # 3. Invalid TTL types
        with pytest.raises(ValidationError):
            CoreasonVaultConfig(VAULT_ADDR="http://localhost", VAULT_TOKEN_TTL="not-an-int")

    def test_failed_encryption_response(self) -> None:
        """
        Verify handling when Vault returns success but missing data fields (malformed response).
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        cipher = TransitCipher(auth)

        # Vault returns something weird (no 'data' key)
        client.secrets.transit.encrypt_data.return_value = {"error": "what?"}

        with pytest.raises(EncryptionError):
            cipher.encrypt("secret", "key")

    def test_failed_decryption_response(self) -> None:
        """
        Verify handling when Vault returns malformed response during decryption.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        cipher = TransitCipher(auth)

        # Vault returns no 'data'
        client.secrets.transit.decrypt_data.return_value = {}

        with pytest.raises(EncryptionError):
            cipher.decrypt("ciphertext", "key")
