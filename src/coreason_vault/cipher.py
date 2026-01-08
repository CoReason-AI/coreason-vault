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

import hvac
import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from coreason_vault.auth import VaultAuthentication
from coreason_vault.exceptions import EncryptionError
from coreason_vault.utils.logger import logger

# Define retryable exceptions
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.RequestException,
    hvac.exceptions.VaultDown,
    hvac.exceptions.InternalServerError,
    hvac.exceptions.BadGateway,
)


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
        """
        try:
            return self._encrypt_impl(plaintext, key_name, context)  # type: ignore[no-any-return]
        except RETRYABLE_EXCEPTIONS as e:
            logger.error(f"Encryption failed after retries: {e}")
            raise EncryptionError(f"Encryption failed due to network error: {e}") from e

    @retry(  # type: ignore[misc]
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _encrypt_impl(self, plaintext: Union[str, bytes], key_name: str, context: Optional[str] = None) -> str:
        client = self.auth.get_client()

        encoded_plaintext = self._encode_base64(plaintext)
        encoded_context = self._encode_base64(context) if context else None

        try:
            response = client.secrets.transit.encrypt_data(
                name=key_name, plaintext=encoded_plaintext, context=encoded_context
            )
            return response["data"]["ciphertext"]  # type: ignore[no-any-return]

        except RETRYABLE_EXCEPTIONS:
            raise
        except Exception as e:
            logger.error(f"Encryption failed for key {key_name}: {e}")
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, ciphertext: str, key_name: str, context: Optional[str] = None) -> Union[str, bytes]:
        """
        Decrypts data using Vault Transit engine.
        """
        try:
            return self._decrypt_impl(ciphertext, key_name, context)  # type: ignore[no-any-return]
        except RETRYABLE_EXCEPTIONS as e:
            logger.error(f"Decryption failed after retries: {e}")
            raise EncryptionError(f"Decryption failed due to network error: {e}") from e

    @retry(  # type: ignore[misc]
        retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _decrypt_impl(self, ciphertext: str, key_name: str, context: Optional[str] = None) -> Union[str, bytes]:
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

        except RETRYABLE_EXCEPTIONS:
            raise
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
