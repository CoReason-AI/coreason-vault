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
from unittest.mock import Mock, patch

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc, unused-ignore]
def mock_auth() -> tuple[Mock, Mock]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock()
    auth.get_client.return_value = client
    return auth, client


def test_keeper_fetch_success(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"key": "value"}}}

    result = keeper.get_secret("path/to/secret")
    assert result == {"key": "value"}
    client.secrets.kv.v2.read_secret_version.assert_called_with(path="path/to/secret", mount_point="secret")


def test_keeper_not_found(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath("Missing")

    with pytest.raises(SecretNotFoundError):
        keeper.get_secret("bad/path")


def test_keeper_permission_denied(mock_auth: Any) -> None:
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden("Denied")

    with pytest.raises(PermissionError):
        keeper.get_secret("secret/path")


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

    # Expire cache (manually clearing for test)
    keeper._cache.clear()

    # Third fetch - hits Vault again
    keeper.get_secret("cached/path")
    assert client.secrets.kv.v2.read_secret_version.call_count == 2
