# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import Mock

import hvac
import pytest
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc, unused-ignore]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock()
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


def test_keeper_fetch_success(mock_auth: Any) -> None:
    auth, client = mock_auth
    # Explicitly set mount point to default "secret" to avoid environment pollution from other tests
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_MOUNT_POINT="secret")
    keeper = SecretKeeper(auth, config)

    # Mock Vault response
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"api_key": "secret-value"}}}

    secret = keeper.get_secret("my/secret")
    assert secret == {"api_key": "secret-value"}

    client.secrets.kv.v2.read_secret_version.assert_called_with(path="my/secret", mount_point="secret")


def test_keeper_caching(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"key": "value"}}}

    # First fetch - hits Vault
    keeper.get_secret("cached/path")
    assert client.secrets.kv.v2.read_secret_version.call_count == 1

    # Second fetch - hits cache
    keeper.get_secret("cached/path")
    assert client.secrets.kv.v2.read_secret_version.call_count == 1

    # Expire cache
    keeper._cache_expiry["cached/path"] = datetime.now() - timedelta(seconds=1)

    # Third fetch - hits Vault again
    keeper.get_secret("cached/path")
    assert client.secrets.kv.v2.read_secret_version.call_count == 2


def test_keeper_not_found(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath

    with pytest.raises(SecretNotFoundError):
        keeper.get_secret("missing/path")


def test_keeper_forbidden(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden

    with pytest.raises(PermissionError):
        keeper.get_secret("restricted/path")


def test_keeper_generic_error(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.side_effect = Exception("Boom")

    with pytest.raises(Exception, match="Boom"):
        keeper.get_secret("path")


def test_keeper_alias_get(mock_auth: Any) -> None:
    """Test that the .get alias works same as .get_secret"""
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"alias": "worked"}}}

    # Call using alias
    result = keeper.get("alias/path")

    assert result == {"alias": "worked"}
    client.secrets.kv.v2.read_secret_version.assert_called_with(path="alias/path", mount_point="secret")
