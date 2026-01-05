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
from unittest.mock import Mock

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, VaultConnectionError
from coreason_vault.keeper import SecretKeeper


# --- Fixtures ---
@pytest.fixture  # type: ignore[misc]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


class TestCoverageGapFill:
    """
    Tests specifically designed to hit lines missed by other tests to achieve 100% coverage.
    """

    def test_auth_reauthentication_failure_generic_exception(self) -> None:
        """
        Cover auth.py:76-80.
        Simulate a token expiration (Forbidden) followed by a generic Exception during re-authentication.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        # 1. Setup initial state: We have a client, but it's expired.
        mock_client = Mock(spec=hvac.Client)
        auth._client = mock_client

        # Ensure we validate token
        auth._last_token_check = 0

        # 2. lookup_self raises Forbidden (Token Expired)
        mock_client.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("Expired")

        # 3. _authenticate raises a generic Exception (not VaultConnectionError)
        # We need to mock _authenticate on the instance
        auth._authenticate = Mock(side_effect=Exception("Generic Auth Failure"))

        # 4. Expect VaultConnectionError wrapping the generic exception
        with pytest.raises(VaultConnectionError) as exc:
            auth.get_client()

        assert "Vault re-authentication failed: Generic Auth Failure" in str(exc.value)

    def test_auth_reauthentication_failure_vault_connection_error(self) -> None:
        """
        Cover auth.py:78 (if isinstance(e, VaultConnectionError): raise).
        Simulate token expiration, then _authenticate raising a VaultConnectionError.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
        auth = VaultAuthentication(config)

        # 1. Setup initial state: client expired.
        mock_client = Mock(spec=hvac.Client)
        auth._client = mock_client
        auth._last_token_check = 0

        # 2. lookup_self raises Forbidden
        mock_client.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("Expired")

        # 3. _authenticate raises VaultConnectionError (e.g. fatal vault error)
        expected_error = VaultConnectionError("Fatal connection error")
        auth._authenticate = Mock(side_effect=expected_error)

        # 4. Expect exact same error re-raised
        with pytest.raises(VaultConnectionError) as exc:
            auth.get_client()

        assert exc.value is expected_error

    def test_cipher_decrypt_network_error(self, mock_auth: Any) -> None:
        """
        Cover cipher.py:73-74.
        Simulate a network error during decryption.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # Simulate network timeout
        client.secrets.transit.decrypt_data.side_effect = requests.exceptions.Timeout("Connect timeout")

        with pytest.raises(EncryptionError) as exc:
            cipher.decrypt("ciphertext", "key")

        assert "Decryption failed due to network error" in str(exc.value)

    def test_cipher_invalid_input_type(self, mock_auth: Any) -> None:
        """
        Cover cipher.py:116.
        Pass an invalid type (int) to _encode_base64 via encrypt.
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        with pytest.raises(TypeError) as exc:
            cipher.encrypt(12345, "key")  # type: ignore[arg-type]

        assert "Expected str or bytes, got <class 'int'>" in str(exc.value)

    def test_keeper_fetch_network_error(self, mock_auth: Any) -> None:
        """
        Cover keeper.py:57-58.
        Simulate a network error during secret fetch.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Simulate network error
        client.secrets.kv.v2.read_secret_version.side_effect = requests.exceptions.ConnectionError("Network Down")

        with pytest.raises(VaultConnectionError) as exc:
            keeper.get_secret("path/to/secret")

        assert "Failed to fetch secret after retries" in str(exc.value)
