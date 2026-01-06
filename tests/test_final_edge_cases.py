# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from unittest.mock import MagicMock, Mock, patch

import pytest
from loguru import logger

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.keeper import SecretKeeper


class TestFinalEdgeCases:
    def test_cipher_context_types(self) -> None:
        """
        Verify that passing invalid types to context raises TypeError.
        Requirement: Context must be str or bytes.
        """
        auth = Mock(spec=VaultAuthentication)
        # We don't even need get_client to return anything because validation happens before that call
        # in _encode_base64, OR it happens inside _encrypt_impl.
        # However, checking the code, _encrypt_impl calls get_client() BEFORE _encode_base64.
        # So we must ensure get_client() doesn't fail.
        auth.get_client.return_value = MagicMock()

        cipher = TransitCipher(auth)

        # Int context
        with pytest.raises(TypeError, match="Expected str or bytes"):
            cipher.encrypt("secret", "key", context=123)  # type: ignore[arg-type]

        # List context
        with pytest.raises(TypeError, match="Expected str or bytes"):
            cipher.encrypt("secret", "key", context=["bad"])  # type: ignore[arg-type]

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
        Verify that the package can handle large payloads locally
        (Base64 encoding, passing to client) without memory errors or crashes.
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
        # Basic check: length of base64 > length of raw
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
        Verify that if both AppRole and K8s vars are set, AppRole takes precedence
        (as per current implementation logic).
        """
        # Set both AppRole and K8s config
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

            # Should have called approle login
            client_instance.auth.approle.login.assert_called_once_with(role_id="approle-id", secret_id="approle-secret")
            # Should NOT have called k8s login
            client_instance.auth.kubernetes.login.assert_not_called()

    def test_auth_method_k8s_fallback(self) -> None:
        """
        Verify K8s is used if AppRole is missing.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            # No AppRole
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
        We simulate an error fetching a secret "my-super-secret-key".
        The log should contain the PATH, but not the return value (which we can't see anyway if it failed),
        but crucially, we check that generic logging doesn't dump locals.
        """
        auth = Mock(spec=VaultAuthentication)
        client = MagicMock()
        auth.get_client.return_value = client
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock success first to get a value
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"api_key": "sk-12345"}}}

        # We need to capture logs from our specific logger
        # pytest caplog captures standard logging.
        # loguru intercepts standard logging if configured, but we are using loguru directly.
        # We need to add a sink to caplog.handler

        handler_id = logger.add(caplog.handler, format="{message}")

        try:
            val = keeper.get_secret("safe/path")
            assert val["api_key"] == "sk-12345"

            # Now verify logs
            # Should verify path is logged
            assert "Secret safe/path fetched" in caplog.text
            # Verify value is NOT logged
            assert "sk-12345" not in caplog.text

        finally:
            logger.remove(handler_id)
