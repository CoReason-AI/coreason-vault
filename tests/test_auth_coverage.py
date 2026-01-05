# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_vault

import time
from typing import Any
from unittest.mock import Mock

import pytest

from coreason_vault.auth import VaultAuthentication
from coreason_vault.config import CoreasonVaultConfig


class TestAuthCoverage:
    """
    Tests specifically targeting uncovered lines in auth.py.
    """

    def test_auth_race_condition_double_check(self) -> None:
        """
        Cover line 51: Double-check inside lock returns existing client.
        We simulate this by having the first check return False (need auth),
        but then 'something' happens before the lock that makes it True?

        Easier way:
        1. Initialize auth with no client.
        2. Mock _should_validate_token to return False (so it looks valid if present).
        3. But initially client is None, so it enters the lock block.
        4. Inside the lock, we want `self._client` to NOT be None.

        How to change `self._client` *after* the first check but *before* the second?
        In a real race, another thread does it.
        In a single-threaded test, we can't easily inject logic *between* the `if` and the `with lock`.

        HOWEVER, we can mock `_lock`.
        If we replace `self._lock` with a mock lock whose `__enter__` side effect
        sets `self._client` to a valid client, then when the code enters `with self._lock`,
        it will see the client is now set, and hit the double-check return.
        """
        config = CoreasonVaultConfig(VAULT_ADDR="http://localhost:8200", VAULT_ROLE_ID="r", VAULT_SECRET_ID="s")
        auth = VaultAuthentication(config)

        # Valid client to be "injected"
        valid_client = Mock()

        # Mock Lock
        original_lock = auth._lock
        mock_lock = Mock()

        def side_effect_enter() -> Any:
            # Simulate another thread having authenticated just now
            auth._client = valid_client
            # Also ensure token validation check passes (we want 'not should_validate')
            # By default _last_token_check is 0, so it WOULD validate.
            # We must set _last_token_check to now.
            auth._last_token_check = time.time()
            return original_lock.acquire()

        def side_effect_exit(*args: Any) -> Any:
            return original_lock.release()

        mock_lock.__enter__ = Mock(side_effect=side_effect_enter)
        mock_lock.__exit__ = Mock(side_effect=side_effect_exit)

        auth._lock = mock_lock

        # Ensure first check fails: client is None
        assert auth._client is None

        # Call get_client
        result = auth.get_client()

        assert result == valid_client
        # Verify we hit the double check return (implicit coverage check, but logic confirms it)

    def test_auth_value_error_propagation(self) -> None:
        """
        Cover lines 105-106: except ValueError: raise.
        We need to trigger a ValueError inside _authenticate logic that is NOT one of the explicit raises.
        Or just ensure one of the explicit raises is caught and re-raised by that specific block.

        The code has:
        try:
          ...
          if ... raise ValueError("Missing Kubernetes role")
          else ... raise ValueError("Missing authentication credentials")
        except ValueError:
          raise

        Any of those raises will hit the except block.
        We just need to ensure we exercise one of them.
        `test_auth_k8s_missing_role` does this.
        Why did coverage report it missing?
        Maybe `pytest --cov` sometimes misses simple `raise` lines?
        Let's explicitly test the "No valid authentication method" path (else block) to be sure.
        """
        config = CoreasonVaultConfig(
            VAULT_ADDR="http://localhost:8200",
            # No Auth credentials provided
        )

        auth = VaultAuthentication(config)

        with pytest.raises(ValueError) as exc:
            auth.get_client()

        assert "Missing authentication credentials" in str(exc.value)
