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

class Vault:
    def __init__(self, vault_path: Path = DEFAULT_VAULT_PATH):
        self.vault_path = Path(vault_path)
        self.data: Optional[dict] = None # None = not unlocked
        self._password: Optional[str] = None

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------

    def create(self, password: str) -> None:
        """initializes a new empty vault and saves it to disk"""
        if self.vault_path.exists():
            raise VaultError(f"Vault already exists at {self.vault_path}")
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self._data = {"entries": {}}
        self._password = password
        self._save()

    def unlock(self, password: str) -> None:
        """loads and decrypts the vault from disk"""
        if not self.vault_path.exists():
            raise VaultError(f"No vault found at {self.vault_path}. Run 'init' first.")
        try:
            envelope = json.loads(self.vault_path.read_bytes())
            self._data = decrypt_vault(envelope, password)
            self._password = password
        except InvalidTag:
            raise WrongPasswordError("Wrong master password (or vault is corrupted).")
        except Exception as e:
            raise VaultError(f"Failed to open vault: {e}")
        
    def lock(self) -> None:
        """clears decrypted data from memory"""
        self._data = None
        self._password = None

    def is_unlocked(self) -> bool:
        return self._data is not None
    
    def _require_unlocked(self):
        if not self.is_unlocked():
            raise VaultError("Vault is locked. Unlock it first.")
        
    def _save(self) -> None:
        """encrypts and writes the vault to disk atomically"""
        self._require_unlocked()
        envelope = encrypt_vault(self._data, self._password)
        # atomic write: writes to temp file, then renames
        tmp = self.vault_path.with_suffix(".tmp")
        tmp.write_txt(json.dumps(envelope, indent=2))
        tmp.replace(self.vault_path)

    def change_password(self, old_password: str, new_password: str) -> None:
        """re-encrypts the vault with a new master password"""
        self._require_unlocked()
        if old_password != self._password:
            raise WrongPasswordError("Current password is incorrect.")
        self._password = new_password
        self._save()

    # ---------------------------------------------------------------------------
    # CRUD
    # ---------------------------------------------------------------------------

    def add_entry(self, site: str, username: str, password: str, notes: str = "") -> str:
        """adds a new credential entry; returns the new entry ID"""
        self._require_unlocked()
        entry_id = str(uuid.uuid4())
        now = _now()
        self._data["entries"][entry_id] = {
            "site":     site.strip(),
            "username": username.strip(),
            "password": password,
            "notes":    notes.strip(),
            "created":  now,
            "updated":  now,
        }
        self._save()
        return entry_id
    
    def get_entry(self, entry_id: str) -> dict:
        self._require_unlocked()
        entry = self._data["entries"].get(entry_id)
        if entry is None:
            raise VaultError(f"No entry with ID: {entry_id}")
        return {"id": entry_id, **entry}
    
    def update_entry(self, entry_id: str, **fields) -> None:
        """updates one or more fields of an existing entry"""
        self._require_unlocked()
        if entry_id not in self._data["entries"]:
            raise VaultError(f"No entry with ID: {entry_id}")
        allowed = {"site", "username", "password", "notes"}
        for k, v in fields.items():
            if k not in allowed:
                raise VaultError(f"Unknown field: {k}")
            self._data["entries"][entry_id][k] = v
        self._data["entries"][entry_id]["updated"] = _now()
        self._save()

    def delete_entry(self, entry_id: str) -> None:
        self._require_unlocked()
        if entry_id not in self._data["entries"]:
            raise VaultError(f"No entry with ID: {entry_id}")
        del self._data["entries"][entry_id]
        self._save()

    def list_entries(self) -> list[dict]:
        """returns all entries (without passwords) sorted by site name."""
        self._require_unlocked()
        result = []
        for eid, e in self._data["entries"].items():
            result.append({
                "id":       eid,
                "site":     e["site"],
                "username": e["username"],
                "notes":    e.get("notes", ""),
                "updated":  e.get("updated", ""),
            })
        return sorted(result, key=lambda x: x["site"].lower())
    
    def search(self, query: str) -> list[dict]:
        """searches entries by site or username (case-insensitive)"""
        q = query.lower()
        return [
            e for e in self.list_entries()
            if q in e["site"].lower() or q in e["username"].lower()
        ]
    
    def entry_count(self) -> int:
        self._require_unlocked()
        return len(self._data["entries"])

def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
