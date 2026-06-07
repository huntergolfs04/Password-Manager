# pypassman — Secure CLI Password Manager

A cybersecurity-focused password manager written in Python, with strong cryptographic foundations.

## Files

| File | Purpose |
|------|---------|
| `pypassman.py` | CLI entry point — all commands |
| `vault.py` | Vault data model & persistence |
| `vault_crypto.py` | Cryptographic core (encryption/decryption) |
| `password_gen.py` | Secure password generator + strength checker |
| `test_pypassman.py` | 25-test suite |

---

## Security Architecture

### Master Password → Encryption Key
The master password is **never stored anywhere**. Instead, it is run through **scrypt** (a memory-hard key derivation function) to produce a 256-bit AES key on-demand:

```
master_password + random_salt  →  scrypt(N=2¹⁷, r=8, p=1)  →  32-byte AES key
```

**Why scrypt?** It's intentionally slow and memory-intensive, making brute-force attacks very expensive even with specialized hardware.

### Vault Encryption
The vault uses **AES-256-GCM** (Galois/Counter Mode):
- **Confidentiality**: AES-256 encrypts all credential data
- **Integrity/Authentication**: GCM's auth tag detects tampering or corruption
- A wrong password or modified ciphertext raises `InvalidTag` immediately

### On-Disk Vault Format
```json
{
  "version": 1,
  "salt":       "<base64, 32 random bytes — new each save>",
  "nonce":      "<base64, 12 random bytes — new each save>",
  "ciphertext": "<base64, AES-256-GCM encrypted vault + auth tag>"
}
```

Every save regenerates fresh salt + nonce → **no key reuse, ever**.

### Password Generation
Uses Python's `secrets` module (backed by `os.urandom`) — **never** the `random` module. Guarantees at least one character from each enabled character class.

---

## Installation

```bash
pip install cryptography
```

That's the only dependency.

---

## Usage

```bash
# Create a new vault
python3 pypassman.py init

# Add a credential (prompts interactively, offers password generation)
python3 pypassman.py add

# List all entries
python3 pypassman.py list

# Retrieve credentials (shows password with --show)
python3 pypassman.py get github
python3 pypassman.py get github --show

# Search
python3 pypassman.py search git

# Edit an entry
python3 pypassman.py edit github

# Delete an entry
python3 pypassman.py delete github

# Generate a standalone password
python3 pypassman.py generate
python3 pypassman.py generate -l 32 --no-symbols --no-ambiguous

# Change master password
python3 pypassman.py passwd

# Use a custom vault location
python3 pypassman.py --vault /path/to/myvault.enc list
```

---

## Running Tests

```bash
python3 test_pypassman.py
```

**25 tests** covering:
- Encrypt/decrypt roundtrip
- Wrong password detection (`InvalidTag`)
- Fresh salt/nonce per save (no key reuse)
- Tamper detection
- Vault CRUD operations
- Persistence across unlock/lock cycles
- Password re-encryption on master password change
- Password generator: length, character classes, uniqueness, ambiguous exclusion

---

## Security Considerations & Future Work

| Topic | Current State | Improvement |
|-------|--------------|-------------|
| Clipboard integration | Not implemented | Add `pyperclip` support; auto-clear after 30s |
| Memory security | Python GC handles it | Use `mlock` + zeroing via `ctypes` for production |
| Vault backup | Single file | Add encrypted export/import command |
| Audit log | None | Log access events (encrypted) |
| TOTP/2FA storage | None | Add TOTP secret storage + code generation |
| Session timeout | Locks on every command | Add daemon mode with configurable timeout |
| Key stretching | scrypt N=2¹⁷ (~0.5s) | Tune N based on hardware benchmark at init |
