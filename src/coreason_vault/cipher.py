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
                     Actually hvac expects base64 encoded string for context if the key is derived.

        Returns:
            Ciphertext string (starts with vault:v1:...)
        """
        client = self.auth.get_client()

        # Prepare plaintext: base64 encode
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            # Handle bytes input
            plaintext_bytes = plaintext

        encoded_plaintext = base64.b64encode(plaintext_bytes).decode("utf-8")

        # Prepare context if present
        encoded_context = None
        if context:
            encoded_context = base64.b64encode(context.encode("utf-8")).decode("utf-8")

        try:
            response = client.secrets.transit.encrypt_data(
                name=key_name, plaintext=encoded_plaintext, context=encoded_context
            )
            ciphertext = response["data"]["ciphertext"]
            # Security: Avoiding excessive logging, but success log is okay
            # logger.info(f"Data encrypted with key {key_name}")
            return ciphertext  # type: ignore[no-any-return]

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
            Decrypted plaintext (as string if possible, else bytes? Spec says "original").
            We will return bytes if input was bytes? No, we don't know original type easily.
            We will return string by default, or bytes?
            Spec says: "Output: Ciphertext string ... or decrypted Plaintext."
            The example shows "Sensitive Patient Data" string in -> string out.
            I will try to decode to utf-8 string, if fail return bytes.
        """
        client = self.auth.get_client()

        # Prepare context if present
        encoded_context = None
        if context:
            encoded_context = base64.b64encode(context.encode("utf-8")).decode("utf-8")

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
            # Ensure binascii.Error (base64 decode fail) is wrapped
            raise EncryptionError(f"Decryption failed: {e}") from e
