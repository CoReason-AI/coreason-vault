# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, SecretNotFoundError
from coreason_vault.manager import VaultManager

__all__ = ["VaultManager", "VaultConfig", "SecretNotFoundError", "EncryptionError"]

# Alias for backward compatibility or easier access if requested
VaultConfig = CoreasonVaultConfig
