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
from unittest.mock import Mock

import hvac
import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import SecretNotFoundError
from coreason_vault.keeper import SecretKeeper


@pytest.fixture  # type: ignore[misc]
def mock_auth() -> Generator[Tuple[Mock, Mock], None, None]:
    auth = Mock(spec=VaultAuthentication)
    client = Mock(spec=hvac.Client)
    auth.get_client.return_value = client
    yield auth, client


def test_dynamic_secret_invalid_path(mock_auth: Any) -> None:
    """
    Test that get_dynamic_secret correctly handles hvac.exceptions.InvalidPath
    by raising SecretNotFoundError.
    """
    auth, client = mock_auth
    config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200")
    keeper = SecretKeeper(auth, config)

    # Simulate InvalidPath exception from hvac
    client.read.side_effect = hvac.exceptions.InvalidPath("Invalid Path")

    with pytest.raises(SecretNotFoundError) as exc:
        keeper.get_dynamic_secret("invalid/path")

    assert "Secret not found: invalid/path" in str(exc.value)
