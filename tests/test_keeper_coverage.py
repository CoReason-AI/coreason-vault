from unittest.mock import MagicMock, Mock

import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.keeper import SecretKeeper


def test_fetch_from_vault_returns_non_dict_data() -> None:
    """
    Test that _fetch_from_vault raises ValueError when Vault returns non-dict data.
    """
    mock_config = Mock(spec=CoreasonVaultConfig)
    mock_config.VAULT_MOUNT_POINT = "secret"
    mock_auth = Mock(spec=VaultAuthentication)

    keeper = SecretKeeper(mock_auth, mock_config)

    # Mock the client and response
    mock_client = MagicMock()
    mock_auth.get_client.return_value = mock_client

    # Simulate Vault returning a list instead of a dict
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": ["not", "a", "dict"]}}

    with pytest.raises(ValueError, match="Expected dict from Vault"):
        keeper._fetch_from_vault("some/path")
