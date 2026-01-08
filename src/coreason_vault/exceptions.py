# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault


class VaultConnectionError(Exception):
    """Raised when Vault is unreachable or authentication fails."""

    pass


class SecretNotFoundError(Exception):
    """Raised when a secret is not found in Vault."""

    pass


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""

    pass
