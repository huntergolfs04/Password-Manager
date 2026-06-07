"""
vault.py — Vault data model and persistence layer.

The vault file on disk is always encrypted (via vault_crypto).
In memory, the vault is a plain dict for easy manipulation.

Vault structure (decrypted):
  {
    "entries": {
      "<entry_id>": {
        "site":     "github.com",
        "username": "alice",
        "password": "s3cr3t!",
        "notes":    "personal account",
        "created":  "2024-06-07T12:00:00",
        "updated":  "2024-06-07T12:00:00"
      },
      ...
    }
  }
"""

import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Optional

from vault_crypto import encrypt_vault, decrypt_vault
from cryptography.exceptions import InvalidTag

DEFAULT_VAULT_PATH = Path.home() / ".pypassman" / "vault.enc"

class VaultError(Exception):
    pass

class WrongPasswordError(VaultError):
    pass