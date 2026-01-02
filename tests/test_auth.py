# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Any, Generator
from unittest.mock import Mock, patch

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import VaultConnectionError


@pytest.fixture
def mock_hvac_client() -> Generator[tuple[Mock, Mock], None, None]:
    with patch("coreason_vault.auth.hvac.Client") as mock:
        client_instance = Mock()
        mock.return_value = client_instance
        # Default to authenticated for successful login flows
        client_instance.is_authenticated.return_value = True
        yield mock, client_instance


def test_auth_approle(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)
    client = auth.get_client()

    assert client == client_instance
    client_instance.auth.approle.login.assert_called_with(role_id="role-id", secret_id="secret-id")
    # Check that is_authenticated was called to verify login success
    assert client_instance.is_authenticated.called


def test_auth_kubernetes(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200",
        KUBERNETES_SERVICE_ACCOUNT_TOKEN="k8s-token",
        VAULT_ROLE_ID="k8s-role",  # Using ROLE_ID as role name
    )

    auth = VaultAuthentication(config)
    client = auth.get_client()

    assert client == client_instance
    client_instance.auth.kubernetes.login.assert_called_with(role="k8s-role", jwt="k8s-token")


def test_auth_missing_creds(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    # Ensure no auth params are set
    config.VAULT_ROLE_ID = None
    config.VAULT_SECRET_ID = None
    config.KUBERNETES_SERVICE_ACCOUNT_TOKEN = None

    auth = VaultAuthentication(config)

    with pytest.raises(ValueError, match="Missing authentication credentials"):
        auth.get_client()


def test_auth_failure_vault_error(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    # Simulate exception during login
    client_instance.auth.approle.login.side_effect = hvac.exceptions.VaultError("Auth failed")

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)

    with pytest.raises(VaultConnectionError, match="Vault authentication failed"):
        auth.get_client()


def test_auth_failure_silent(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    # Simulate login returning but is_authenticated is False
    client_instance.is_authenticated.return_value = False

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)

    with pytest.raises(VaultConnectionError, match="Vault authentication failed silently"):
        auth.get_client()


def test_auth_unexpected_error(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client
    # Simulate generic exception during login
    client_instance.auth.approle.login.side_effect = Exception("Unexpected")

    config = CoreasonVaultConfig(
        VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="role-id", VAULT_SECRET_ID="secret-id"
    )

    auth = VaultAuthentication(config)

    with pytest.raises(Exception, match="Unexpected"):
        auth.get_client()


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

    # Second call: verifies client1 is bad, calls _authenticate, which creates client2
    c2 = auth.get_client()
    assert c2 == client2_mock
    assert auth._client == client2_mock


def test_auth_kubernetes_missing_role(mock_hvac_client: Any) -> None:
    mock_class, client_instance = mock_hvac_client

    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", KUBERNETES_SERVICE_ACCOUNT_TOKEN="k8s-token")
    # Role ID is missing
    config.VAULT_ROLE_ID = None

    auth = VaultAuthentication(config)

    with pytest.raises(ValueError, match="Missing Kubernetes role"):
        auth.get_client()
