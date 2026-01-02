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
from unittest.mock import ANY, Mock

import pytest

from coreason_vault.cipher import TransitCipher
from coreason_vault.exceptions import EncryptionError


@pytest.fixture
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock()
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


def test_cipher_encrypt(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    # Mock Vault response
    client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:ciphertext"}}

    result = cipher.encrypt("secret data", "my-key")
    assert result == "vault:v1:ciphertext"

    # Verify call arguments
    # "secret data" -> base64
    expected_b64 = base64.b64encode(b"secret data").decode("utf-8")
    client.secrets.transit.encrypt_data.assert_called_with(name="my-key", plaintext=expected_b64, context=None)


def test_cipher_encrypt_with_context(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:ciphertext"}}

    cipher.encrypt("secret data", "my-key", context="user-123")

    expected_context = base64.b64encode(b"user-123").decode("utf-8")
    client.secrets.transit.encrypt_data.assert_called_with(name="my-key", plaintext=ANY, context=expected_context)


def test_cipher_decrypt(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    # Mock Vault response
    # Plaintext "secret data" -> base64
    b64_plaintext = base64.b64encode(b"secret data").decode("utf-8")
    client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": b64_plaintext}}

    result = cipher.decrypt("vault:v1:ciphertext", "my-key")
    assert result == "secret data"

    client.secrets.transit.decrypt_data.assert_called_with(
        name="my-key", ciphertext="vault:v1:ciphertext", context=None
    )


def test_cipher_decrypt_binary(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    # Binary data that is not valid utf-8
    binary_data = b"\x80\x81"
    b64_plaintext = base64.b64encode(binary_data).decode("utf-8")

    client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": b64_plaintext}}

    result = cipher.decrypt("vault:v1:ciphertext", "my-key")
    assert result == binary_data


def test_cipher_encrypt_error(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    client.secrets.transit.encrypt_data.side_effect = Exception("Encryption failed")

    with pytest.raises(EncryptionError):
        cipher.encrypt("data", "key")


def test_cipher_decrypt_error(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    client.secrets.transit.decrypt_data.side_effect = Exception("Decryption failed")

    with pytest.raises(EncryptionError):
        cipher.decrypt("cipher", "key")


def test_cipher_encrypt_bytes(mock_auth: Any) -> None:
    auth, client = mock_auth
    cipher = TransitCipher(auth)

    client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:ciphertext"}}

    # Pass bytes directly
    result = cipher.encrypt(b"secret data", "my-key")
    assert result == "vault:v1:ciphertext"
