# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import threading
import time
from typing import Any, Dict
from unittest.mock import Mock

import pytest
import requests
from hvac import exceptions

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.keeper import SecretKeeper


class TestAdvancedScenarios:
    """
    Advanced scenarios covering concurrency, rate limiting, and time-based edge cases.
    """

    def test_concurrency_cache_stampede(self) -> None:
        """
        Verify that multiple threads requesting the same secret simultaneously
        result in only ONE call to the underlying Vault API.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = Mock(spec=VaultAuthentication)
        client = Mock()
        auth.get_client.return_value = client

        # Mock response
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"api_key": "123"}}}

        # Add a small delay to the mock to simulate network latency,
        # ensuring threads pile up waiting for the lock.
        def delayed_response(*args: Any, **kwargs: Any) -> Dict[str, Any]:
            time.sleep(0.05)
            return {"data": {"data": {"api_key": "123"}}}

        client.secrets.kv.v2.read_secret_version.side_effect = delayed_response

        keeper = SecretKeeper(auth, config)

        def fetch_secret() -> None:
            keeper.get_secret("concurrent/secret")

        threads = []
        for _ in range(10):
            t = threading.Thread(target=fetch_secret)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Assert that read_secret_version was called exactly ONCE
        # thanks to the lock in SecretKeeper.
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

    def test_rate_limiting_handling(self) -> None:
        """
        Verify that a 429 Too Many Requests response is handled gracefully.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = Mock(spec=VaultAuthentication)
        client = Mock()
        auth.get_client.return_value = client

        response = requests.Response()
        response.status_code = 429
        # hvac raises unexpected error for 429 usually
        error = exceptions.VaultError(message="Rate limit exceeded", errors=["429"])

        client.secrets.kv.v2.read_secret_version.side_effect = error
        keeper = SecretKeeper(auth, config)

        with pytest.raises(exceptions.VaultError):
            keeper.get_secret("rate/limited")

    def test_cache_expiry_logic(self) -> None:
        """
        Verify that the cache expires after the TTL.
        Using cachetools.TTLCache makes this test tricky because it relies on internal time.
        We can't easily patch time inside the C-extension or library unless we inject a timer.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = Mock(spec=VaultAuthentication)
        client = Mock()
        auth.get_client.return_value = client

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"val": "1"}}}

        # Create keeper with very short TTL
        keeper = SecretKeeper(auth, config)
        # Manually replace cache with a short TTL for testing
        from cachetools import TTLCache

        keeper._cache = TTLCache(maxsize=10, ttl=0.1)

        # 1. Fetch first time (miss)
        keeper.get_secret("my/secret")
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # 2. Fetch immediately (hit)
        keeper.get_secret("my/secret")
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # 3. Wait for TTL
        time.sleep(0.15)

        # 4. Should be a cache miss -> fetch again
        keeper.get_secret("my/secret")
        assert client.secrets.kv.v2.read_secret_version.call_count == 2
