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

from coreason_vault import VaultConfig, VaultManager


def test_manager_initialization() -> None:
    config = VaultConfig(VAULT_ADDR="http://localhost:8200")
    manager = VaultManager(config)

    assert manager.config == config
    assert manager.auth is not None
    assert manager.secrets is not None
    assert manager.cipher is not None

    # Verify relationships
    assert manager.secrets.auth == manager.auth
    assert manager.cipher.auth == manager.auth


@patch("coreason_vault.auth.hvac.Client")
def test_manager_workflow(mock_hvac_class: Any) -> None:
    # Integration-like test mocking hvac at the lowest level
    client_mock = Mock()
    mock_hvac_class.return_value = client_mock
    client_mock.is_authenticated.return_value = True

    # Setup mocks for secrets and transit
    client_mock.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"api_key": "12345"}}}
    client_mock.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:abc"}}
    client_mock.secrets.transit.decrypt_data.return_value = {
        "data": {"plaintext": "c2VjcmV0"}  # base64 for "secret"
    }

    config = VaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="my-role", VAULT_SECRET_ID="my-secret")
    vault = VaultManager(config)

    # 1. Fetch Secret
    creds = vault.secrets.get_secret("coreason/services/openai")
    assert creds["api_key"] == "12345"

    # 2. Encrypt
    ciphertext = vault.cipher.encrypt(plaintext="secret", key_name="patient-data-key", context="user_123")
    assert ciphertext == "vault:v1:abc"

    # 3. Decrypt
    original = vault.cipher.decrypt(ciphertext=ciphertext, key_name="patient-data-key", context="user_123")
    assert original == "secret"
