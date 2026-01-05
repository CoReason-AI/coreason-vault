# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import time
from unittest.mock import Mock

from cachetools import TTLCache

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.keeper import SecretKeeper


class TestRefactorEdgeCases:
    """
    Tests specifically targeting edge cases introduced by the refactoring
    (Cachetools, Token Validation Interval).
    """

    def test_keeper_cache_eviction_maxsize(self) -> None:
        """
        Verify that the cache respects the maxsize limit and evicts old entries.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = Mock(spec=VaultAuthentication)
        client = Mock()
        auth.get_client.return_value = client

        # Mock Vault returning simple data
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"val": "1"}}}

        keeper = SecretKeeper(auth, config)

        # Manually replace cache with a small maxsize for testing
        # We use a small TTL so we don't have to wait, but here we test maxsize
        keeper._cache = TTLCache(maxsize=3, ttl=60)

        # Fill cache
        keeper.get_secret("s1")
        keeper.get_secret("s2")
        keeper.get_secret("s3")

        assert len(keeper._cache) == 3
        assert "s1" in keeper._cache

        # Add 4th item, should evict one (LRU by default in cachetools? TTLCache is LRU-like)
        keeper.get_secret("s4")

        assert len(keeper._cache) == 3
        assert "s4" in keeper._cache
        # s1 was least recently used (accessed first, never again), so likely evicted
        assert "s1" not in keeper._cache

    def test_auth_token_validation_interval(self) -> None:
        """
        Verify that token validation is skipped if within the interval,
        and performed if interval passed.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="r", VAULT_SECRET_ID="s")
        auth = VaultAuthentication(config)

        # Mock client
        client = Mock()
        client.is_authenticated.return_value = True

        # Inject client
        auth._client = client
        # Pretend we just validated
        auth._last_token_check = time.time()
        auth.TOKEN_VALIDATION_INTERVAL = 10  # Set explicitly

        # 1. Call immediately - should SKIP lookup_self
        auth.get_client()
        client.auth.token.lookup_self.assert_not_called()

        # 2. Simulate time passing > interval
        # We can just change _last_token_check to be old
        auth._last_token_check = time.time() - 11

        auth.get_client()
        client.auth.token.lookup_self.assert_called_once()
