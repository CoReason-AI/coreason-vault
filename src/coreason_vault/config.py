# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonVaultConfig(BaseSettings):  # type: ignore[misc, unused-ignore]
    """
    Configuration for the Coreason Vault package.
    Loads settings from environment variables.
    """

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=True, extra="ignore")

    # Vault Connection
    VAULT_ADDR: str = Field(..., description="The URL of the Vault server")
    VAULT_NAMESPACE: Optional[str] = Field(default=None, description="The Vault namespace")

    # Auth Methods
    VAULT_ROLE_ID: Optional[str] = Field(default=None, description="AppRole Role ID")
    VAULT_SECRET_ID: Optional[str] = Field(default=None, description="AppRole Secret ID")
    KUBERNETES_SERVICE_ACCOUNT_TOKEN: Optional[str] = Field(default=None, description="Kubernetes SA Token for auth")

    # Mount Points
    VAULT_MOUNT_POINT: str = Field(default="secret", description="KV v2 Mount Point")

    # Optional
    VAULT_VERIFY_SSL: bool = Field(default=True, description="Verify SSL certificates")
