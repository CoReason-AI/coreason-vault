# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

from coreason_vault.auth import VaultAuthentication
from coreason_vault.cipher import TransitCipher
from coreason_vault.config import CoreasonVaultConfig
from coreason_vault.exceptions import EncryptionError, SecretNotFoundError
from coreason_vault.keeper import SecretKeeper


class VaultManager:
    """
    The main entry point for the Coreason Vault package.
    Initializes and coordinates authentication, secret retrieval, and encryption services.
    """

    def __init__(self, config: CoreasonVaultConfig):
        self.config = config
        self.auth = VaultAuthentication(config)
        self.secrets = SecretKeeper(self.auth, config)
        self.cipher = TransitCipher(self.auth)


# Export Exceptions for easier access
__all__ = [
    "VaultManager",
    "CoreasonVaultConfig",
    "SecretNotFoundError",
    "EncryptionError",
]
