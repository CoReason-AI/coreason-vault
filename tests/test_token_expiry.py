# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from unittest.mock import Mock

import hvac

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig


def test_auth_token_expiring_soon() -> None:
    """
    Verify that if the token TTL is too low (< 10s), we treat it as expired
    and trigger re-authentication.
    """
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role", VAULT_SECRET_ID="secret")
    auth = VaultAuthentication(config)

    # 1. Setup: Existing client with low TTL
    stale_client = Mock(spec=hvac.Client)
    stale_client.auth.token.lookup_self.return_value = {"data": {"ttl": 5}}  # 5 seconds left

    fresh_client = Mock(spec=hvac.Client)
    fresh_client.is_authenticated.return_value = True
    fresh_client.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}

    auth._client = stale_client
    auth._last_token_check = 0  # Force check

    # Mock _authenticate to return fresh client
    # Using side_effect to return fresh_client when called
    auth._authenticate = Mock(return_value=fresh_client)

    # 2. Action
    client = auth.get_client()

    # 3. Assertions
    # Should have checked stale client
    stale_client.auth.token.lookup_self.assert_called_once()

    # Should have called authenticate
    auth._authenticate.assert_called_once()

    # Should return fresh client
    assert client == fresh_client
