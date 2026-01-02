# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import os

import pytest
from pydantic import ValidationError

from coreason_vault.config import CoreasonVaultConfig


def test_config_defaults() -> None:
    """Test that default values are set correctly."""
    # We need VAULT_ADDR at minimum
    os.environ["VAULT_ADDR"] = "http://localhost:8200"
    config = CoreasonVaultConfig()
    assert config.VAULT_ADDR == "http://localhost:8200"
    assert config.VAULT_MOUNT_POINT == "secret"
    assert config.VAULT_VERIFY_SSL is True
    assert config.VAULT_NAMESPACE is None


def test_config_env_overrides() -> None:
    """Test that environment variables override defaults."""
    os.environ["VAULT_ADDR"] = "https://vault.example.com"
    os.environ["VAULT_MOUNT_POINT"] = "custom_secret"
    os.environ["VAULT_VERIFY_SSL"] = "false"
    os.environ["VAULT_NAMESPACE"] = "admin"

    config = CoreasonVaultConfig()
    assert config.VAULT_ADDR == "https://vault.example.com"
    assert config.VAULT_MOUNT_POINT == "custom_secret"
    assert config.VAULT_VERIFY_SSL is False
    assert config.VAULT_NAMESPACE == "admin"


def test_config_missing_required() -> None:
    """Test that missing required fields raise validation error."""
    if "VAULT_ADDR" in os.environ:
        del os.environ["VAULT_ADDR"]

    with pytest.raises(ValidationError):
        CoreasonVaultConfig()


def test_config_extra_ignore() -> None:
    """Test that extra environment variables are ignored."""
    os.environ["VAULT_ADDR"] = "http://localhost:8200"
    os.environ["SOME_RANDOM_VAR"] = "value"

    config = CoreasonVaultConfig()
    assert not hasattr(config, "SOME_RANDOM_VAR")
