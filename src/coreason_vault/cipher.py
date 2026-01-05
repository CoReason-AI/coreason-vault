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
from typing import Optional, Union

from coreason_vault.auth import VaultAuthentication
from coreason_vault.exceptions import EncryptionError
from coreason_vault.utils.logger import logger


class TransitCipher:
    """
    Provides Encryption as a Service (EaaS) using Vault's Transit Secret Engine.
    Handles Base64 encoding/decoding and context derivation.
    """

    def __init__(self, auth: VaultAuthentication):
        self.auth = auth

    def encrypt(self, plaintext: Union[str, bytes], key_name: str, context: Optional[str] = None) -> str:
        """
        Encrypts data using Vault Transit engine.

        Args:
            plaintext: Data to encrypt (string or bytes).
            key_name: The name of the encryption key in Vault.
            context: Optional context for key derivation (must be base64 encoded if passed to hvac,
                     but we accept raw string and handle encoding).

        Returns:
            Ciphertext string (starts with vault:v1:...)
        """
        client = self.auth.get_client()

        encoded_plaintext = self._encode_base64(plaintext)
        encoded_context = self._encode_base64(context) if context else None

        try:
            response = client.secrets.transit.encrypt_data(
                name=key_name, plaintext=encoded_plaintext, context=encoded_context
            )
            return response["data"]["ciphertext"]  # type: ignore[no-any-return]

        except Exception as e:
            logger.error(f"Encryption failed for key {key_name}: {e}")
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext: str, key_name: str, context: Optional[str] = None) -> Union[str, bytes]:
        """
        Decrypts data using Vault Transit engine.

        Args:
            ciphertext: The ciphertext string (vault:v1:...).
            key_name: The name of the encryption key.
            context: Optional context used during encryption.

        Returns:
            Decrypted plaintext (as string if possible, else bytes).
        """
        client = self.auth.get_client()

        encoded_context = self._encode_base64(context) if context else None

        try:
            response = client.secrets.transit.decrypt_data(
                name=key_name, ciphertext=ciphertext, context=encoded_context
            )
            encoded_plaintext = response["data"]["plaintext"]

            # Decode base64
            plaintext_bytes = base64.b64decode(encoded_plaintext, validate=True)

            try:
                return plaintext_bytes.decode("utf-8")
            except UnicodeDecodeError:  # pragma: no cover
                return plaintext_bytes  # pragma: no cover

        except Exception as e:
            logger.error(f"Decryption failed for key {key_name}: {e}")
            raise EncryptionError(f"Decryption failed: {e}") from e

    def _encode_base64(self, data: Union[str, bytes]) -> str:
        """
        Helper to encode input data (string or bytes) to a base64 string.
        """
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise TypeError(f"Expected str or bytes, got {type(data)}")

        return base64.b64encode(data_bytes).decode("utf-8")
