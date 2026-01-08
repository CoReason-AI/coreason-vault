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
from typing import Any, Generator, Tuple
from unittest.mock import Mock

import hvac
import pytest
import requests

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> Generator[Tuple[Mock, Mock], None, None]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    yield auth, client


class TestDynamicSecretsComplex:
    def test_concurrent_dynamic_fetches(self, mock_auth: Any) -> None:
        """
        Verify that multiple threads can fetch dynamic secrets concurrently.
        Since get_dynamic_secret does not use the lock, this primarily tests
        that no unexpected race conditions occur in the client usage.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Mock response
        client.read.return_value = {"data": {"user": "db_user"}, "lease_duration": 300}

        def worker() -> None:
            # Add small random sleep to mix execution
            time.sleep(0.001)
            res = keeper.get_dynamic_secret("database/creds/read-only")
            assert res["data"]["user"] == "db_user"

        threads = []
        for _ in range(20):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert client.read.call_count == 20

    def test_large_dynamic_payload(self, mock_auth: Any) -> None:
        """
        Verify handling of large response payloads (e.g. large PKI certificate chains).
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Create a 1MB payload
        large_cert = "BEGIN CERTIFICATE\n" + ("A" * 1024 * 1024) + "\nEND CERTIFICATE"
        mock_response = {
            "data": {
                "certificate": large_cert,
                "private_key": "private...",
                "ca_chain": ["cert1", "cert2"]
            },
            "lease_duration": 7200
        }
        client.read.return_value = mock_response

        res = keeper.get_dynamic_secret("pki/issue/my-role")
        assert len(res["data"]["certificate"]) > 1000000
        assert res["lease_duration"] == 7200

    def test_pki_response_structure(self, mock_auth: Any) -> None:
        """
        Verify that a typical PKI response structure is preserved exactly.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        pki_response = {
            "request_id": "req-123",
            "lease_id": "pki/issue/role/lease-123",
            "lease_duration": 3600,
            "renewable": False,
            "data": {
                "certificate": "cert-data",
                "issuing_ca": "ca-data",
                "private_key": "key-data",
                "private_key_type": "rsa",
                "serial_number": "00:11:22:33"
            },
            "warnings": None
        }
        client.read.return_value = pki_response

        res = keeper.get_dynamic_secret("pki/issue/role")
        assert res["lease_id"] == "pki/issue/role/lease-123"
        assert res["data"]["serial_number"] == "00:11:22:33"

    def test_mixed_success_failure(self, mock_auth: Any) -> None:
        """
        Verify intermittent network failures (fail twice, then succeed).
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # Fail twice with connection error, then succeed
        client.read.side_effect = [
            requests.exceptions.ConnectionError("Fail 1"),
            requests.exceptions.ConnectionError("Fail 2"),
            {"data": {"k": "v"}}
        ]

        res = keeper.get_dynamic_secret("aws/creds/role")
        assert res["data"]["k"] == "v"
        assert client.read.call_count == 3

    def test_retry_on_server_errors(self, mock_auth: Any) -> None:
        """
        Verify that 5xx errors (InternalServerError, BadGateway) trigger retries.
        Currently, the code retries on RequestException and VaultDown.
        We need to ensure hvac 5xx exceptions are covered.
        """
        auth, client = mock_auth
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
        keeper = SecretKeeper(auth, config)

        # hvac.exceptions.InternalServerError is a VaultError.
        # If the code only catches VaultDown, this test might fail (which reveals a gap).
        # We simulate a 500 error then success.

        # Note: hvac raises specific exceptions based on status code.
        # 500 -> InternalServerError
        # 502 -> BadGateway
        # 503 -> ServiceUnavailable

        client.read.side_effect = [
            hvac.exceptions.InternalServerError("500 Error"),
            {"data": {"success": True}}
        ]

        # If strict policy: raise VaultError (not VaultDown) -> Test fails (raises InternalServerError)
        # If loose policy: retry -> success

        # We expect it might fail based on current implementation, so we catch exception to verify behavior
        # But ideally we WANT it to retry.

        try:
            res = keeper.get_dynamic_secret("flaky/path")
            assert res["data"]["success"] is True
            assert client.read.call_count == 2
        except hvac.exceptions.InternalServerError:
             pytest.fail("Did not retry on InternalServerError")
