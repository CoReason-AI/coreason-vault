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
from datetime import datetime, timedelta
from typing import Any, Dict
from unittest.mock import Mock, patch

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
        Uses mocking of datetime to simulate time passage.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        auth = Mock(spec=VaultAuthentication)
        client = Mock()
        auth.get_client.return_value = client

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"val": "1"}}}

        keeper = SecretKeeper(auth, config)
        keeper.cache_ttl = 60

        # 1. Fetch first time (miss)
        keeper.get_secret("my/secret")
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # 2. Fetch immediately (hit)
        keeper.get_secret("my/secret")
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # 3. Simulate time passing > 60s
        fake_now = datetime.now() + timedelta(seconds=61)
        with patch("coreason_vault.keeper.datetime") as mock_dt:
            # We must mock now() to return our future time
            # AND we must assume the previous calls used "real" time or compatible time.
            # The cache stored "expiry = real_now + 60".
            # our mock_dt.now() returns "real_now + 61".
            mock_dt.now.return_value = fake_now

            keeper.get_secret("my/secret")

            # Should be a cache miss -> fetch again
            assert client.secrets.kv.v2.read_secret_version.call_count == 2
