"""
vault_crypto.py — Cryptographic core for the password manager vault.

Design decisions:
  - Master password → key derivation via scrypt (N=2^17, r=8, p=1)
  - Vault encryption: AES-256-GCM (authenticated encryption — confidentiality + integrity)
  - Each save generates a fresh random salt + nonce (no key reuse)
  - Vault format: JSON envelope with base64-encoded ciphertext/tag/salt/nonce
"""
import os
import json
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# constants
SALT_LEN = 32 # bytes
NONCE_LEN = 12 # bytes (96-bit nonce for AES-GCM)
KEY_LEN = 32 # bytes -> AES-256

# scrypt parameters - tuned for ~0.5s on modern hardware
SCRYPT_N = 2 ** 17 # CPU/memory cost
SCRYPT_R = 8 # block size
SCRYPT_P = 1 # parallelism

def _derive_key(password: str, salt: bytes) -> bytes:
    """ derives a 256-bit key from a master password + salt using scrypt """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))

def encrypt_vault(plaintext_data: dict, password: str) -> dict:
    """
    serializes and encrypt a vault dict.

    returns a JSON-serializable envelope:
      {
        "version": 1,
        "salt":    <base64>,
        "nonce":   <base64>,
        "ciphertext": <base64>,   # includes GCM auth tag appended by AESGCM
      }
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)

    plaintext = json.dumps(plaintext_data, separators=(",", ":")).encode("utf-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None) # no additional data

    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_vault(envelope: dict, password: str) -> dict:
    """
    decrypts and deserializes a vault envelope.

    raises:
      InvalidTag - wrong password or tampered ciphertext
      ValueError - malformed envelope
      KeyError - missing envelope fields
    """
    try:
        salt       = base64.b64decode(envelope["salt"])
        nonce      = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except (KeyError, Exception) as e:
        raise ValueError(f"Malformed vault envelope: {e}")

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    # InvalidTag is raised here on wrong password or corruption
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))