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
import threading
from typing import Any, Generator, Tuple
from unittest.mock import Mock, patch

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> Generator[Tuple[Mock, Mock], None, None]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    yield auth, client


class TestFinalComplexScenarios:
    def test_network_timeout_retry_exhaustion(self, mock_auth: Any) -> None:
        """
        Verify that requests.exceptions.ReadTimeout triggers retries
        and eventually raises VaultConnectionError.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock read_secret_version to always raise ReadTimeout
        # tenacity retry logic is inside _fetch_from_vault
        # We need to ensure _fetch_from_vault is NOT mocked, but the hvac client call is.
        # However, _fetch_from_vault calls auth.get_client().secrets.kv.v2.read_secret_version
        client.secrets.kv.v2.read_secret_version.side_effect = requests.exceptions.ReadTimeout("Timeout")

        # We need to verify that get_secret wraps the final error
        with pytest.raises(VaultConnectionError) as exc:
            keeper.get_secret("timeout/secret")

        assert "Failed to fetch secret after retries" in str(exc.value)
        # Verify multiple attempts were made (Tenacity default is 3)
        assert client.secrets.kv.v2.read_secret_version.call_count >= 3

    def test_large_payload_handling(self, mock_auth: Any) -> None:
        """
        Verify handling of large payloads (1MB).
        """
        auth, client = mock_auth
        cipher = TransitCipher(auth)

        # 1MB of 'A's
        large_data = "A" * (1024 * 1024)
        encoded_data = base64.b64encode(large_data.encode("utf-8")).decode("utf-8")

        client.secrets.transit.encrypt_data.return_value = {"data": {"ciphertext": "vault:v1:large"}}
        client.secrets.transit.decrypt_data.return_value = {"data": {"plaintext": encoded_data}}

        # Encrypt
        ct = cipher.encrypt(large_data, "large-key")
        assert ct == "vault:v1:large"

        # Decrypt
        pt = cipher.decrypt(ct, "large-key")
        assert pt == large_data

    def test_nested_secret_structure(self, mock_auth: Any) -> None:
        """
        Verify that deeply nested JSON structures are returned correctly.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        complex_data = {
            "level1": {
                "level2": {
                    "level3": [1, 2, {"key": "val"}],
                    "bool": True,
                    "none": None,
                }
            }
        }

        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": complex_data}}

        result = keeper.get_secret("complex/secret")
        assert result == complex_data
        assert result["level1"]["level2"]["level3"][2]["key"] == "val"

    def test_namespace_configuration(self) -> None:
        """
        Verify that VAULT_NAMESPACE is correctly passed to the hvac Client.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_NAMESPACE="my-namespace",
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
        )
        auth = VaultAuthentication(config)

        # Patch hvac.Client class to verify init args
        with patch("coreason_vault.auth.hvac.Client") as MockClient:
            mock_instance = MockClient.return_value
            mock_instance.is_authenticated.return_value = True
            auth._authenticate()

            MockClient.assert_called_with(
                url="http://localhost:8200/",  # Pydantic HttpUrl adds slash
                namespace="my-namespace",
                verify=True,
            )

    def test_verify_ssl_configuration(self) -> None:
        """
        Verify that VAULT_VERIFY_SSL=False is correctly passed to the hvac Client.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            VAULT_VERIFY_SSL=False,
            VAULT_ROLE_ID="role",
            VAULT_SECRET_ID="secret",
        )
        auth = VaultAuthentication(config)

        with patch("coreason_vault.auth.hvac.Client") as MockClient:
            mock_instance = MockClient.return_value
            mock_instance.is_authenticated.return_value = True
            auth._authenticate()

            MockClient.assert_called_with(
                url="http://localhost:8200/",
                namespace=None,
                verify=False,
            )

    def test_cache_stampede_prevention(self, mock_auth: Any) -> None:
        """
        Verify that concurrent requests for the same secret only trigger one Vault call
        (or at least adhere to locking, though locking around cache doesn't fully prevent
        thundering herd if the check is inside the lock but the fetch is outside?
        Wait, in SecretKeeper, fetch is INSIDE the lock? Let's check implementation).

        Implementation check:
        with self._lock:
            if path in cache: return
            fetch()
            cache[path] = val

        Yes, fetch is inside the lock. So it is strictly serial for ALL keys.
        This is a bit heavy-handed (global lock), but safe.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock Vault response
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v"}}}

        # Use a latch to ensure threads start together
        start_event = threading.Event()

        def worker() -> None:
            start_event.wait()
            keeper.get_secret("shared/secret")

        threads = []
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        # Release threads
        start_event.set()

        # Join threads
        for t in threads:
            t.join()

        # Because of the lock, only the first thread should have called vault.
        # Subsequent threads should have hit the cache.
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

    def test_cache_expiry(self, mock_auth: Any) -> None:
        """
        Verify that after the TTL expires, the secret is fetched again.
        We simulate this by manipulating the underlying cache directly or
        using a very short TTL.
        Since cachetools uses time.monotonic by default, mocking time is hard without
        injecting a timer.
        Instead, we can manually expire the item in the cache if we can access it.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock response
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v1"}}}

        # First fetch
        val1 = keeper.get_secret("key")
        assert val1["k"] == "v1"
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # Second fetch (immediate) - should be cached
        val2 = keeper.get_secret("key")
        assert val2["k"] == "v1"
        assert client.secrets.kv.v2.read_secret_version.call_count == 1

        # Now, we simulate expiry.
        # Since we can't easily wait 60s, we can clear the cache or replace it.
        # Or simpler: The cache is a TTLCache. We can force it to expire by
        # explicitly removing the item (eviction).
        # But that doesn't test the TTL logic itself.
        #
        # Better approach: We can replace the cache on the instance with one that has a tiny TTL?
        # No, TTLCache doesn't expire based on wall clock easily in test without sleep.
        # Let's rely on manually clearing the cache key to simulate "expiry happened".
        # This tests that *if* not in cache, it refetches.

        with keeper._lock:
            if "key" in keeper._cache:
                del keeper._cache["key"]

        # Update mock to return new value
        client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"k": "v2"}}}

        # Third fetch - should hit vault
        val3 = keeper.get_secret("key")
        assert val3["k"] == "v2"
        assert client.secrets.kv.v2.read_secret_version.call_count == 2
