# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Any, Generator, Tuple
from unittest.mock import Mock, patch

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError


@pytest.fixture  # type: ignore[misc]
def mock_hvac_client() -> Generator[Tuple[Mock, Mock], None, None]:
    with patch("coreason_vault.auth.hvac.Client") as MockClient:
        # Return the class mock and the instance mock
        yield MockClient, MockClient.return_value


def test_auth_approle(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    client_instance.is_authenticated.return_value = True

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)
    client = auth.get_client()

    assert client == client_instance
    client_instance.auth.approle.login.assert_called_with(role_id="role-id", secret_id="secret-id")


def test_auth_k8s(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    client_instance.is_authenticated.return_value = True

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200",
        VAULT_K8S_ROLE="k8s-role",
        KUBERNETES_SERVICE_ACCOUNT_TOKEN="jwt-token",
    )

    auth = VaultAuthentication(config)
    client = auth.get_client()

    assert client == client_instance
    client_instance.auth.kubernetes.login.assert_called_with(role="k8s-role", jwt="jwt-token")


def test_auth_k8s_missing_role(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200",
        KUBERNETES_SERVICE_ACCOUNT_TOKEN="jwt-token",
    )
    # Missing role
    config.VAULT_K8S_ROLE = None

    auth = VaultAuthentication(config)
    with pytest.raises(ValueError):
        auth.get_client()


def test_auth_failure_vault_error(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    client_instance.auth.approle.login.side_effect = hvac.exceptions.VaultError("Auth failed")

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)
    with pytest.raises(VaultConnectionError):
        auth.get_client()


def test_auth_failure_not_authenticated(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    client_instance.is_authenticated.return_value = False

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)
    with pytest.raises(VaultConnectionError):
        auth.get_client()


def test_token_renewal_check(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    client_instance.is_authenticated.return_value = True

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )
    auth = VaultAuthentication(config)

    # First call - authenticates
    auth.get_client()

    # Second call - should check token
    # But wait, now we have a TTL.
    # We need to expire the TTL to force a check.
    auth._last_token_check = 0  # Force check

    # Mock return value for lookup_self to include TTL
    client_instance.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}

    auth.get_client()
    client_instance.auth.token.lookup_self.assert_called_once()


def test_reauthentication(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)

    # 1. Reset mock to use side_effect for instantiation
    client1_mock = Mock()
    client1_mock.is_authenticated.return_value = True

    client2_mock = Mock()
    client2_mock.is_authenticated.return_value = True

    mock_class.return_value = None  # Clear return_value to use side_effect
    mock_class.side_effect = [client1_mock, client2_mock]

    # First call: creates client1
    c1 = auth.get_client()
    assert c1 == client1_mock

    # Now make client1 expired by raising Forbidden on lookup_self
    client1_mock.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("Token expired")

    # FORCE Check
    auth._last_token_check = 0

    # Second call: verifies client1 is bad, calls _authenticate, which creates client2
    c2 = auth.get_client()
    assert c2 == client2_mock
