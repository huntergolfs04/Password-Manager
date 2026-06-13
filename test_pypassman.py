"""
test_pypassman.py - Test suite for vault crypto, vault model, and password generator.
Run with: python3 test_pypassman.py
"""

import sys
import os
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from vault_crypto import encrypt_vault, decrypt_vault
from vault import Vault, VaultError, WrongPasswordError
from password_gen import generate_password, password_strength
from cryptography.exceptions import InvalidTag


class TestVaultCrypto(unittest.TestCase):

    def test_roundtrip(self):
        data = {"entries": {"abc": {"site": "example.com", "password": "s3cr3t"}}}
        envelope = encrypt_vault(data, "masterpassword")
        result = decrypt_vault(envelope, "masterpassword")
        self.assertEqual(result, data)

    def test_wrong_password_raises(self):
        data = {"entries": {}}
        envelope = encrypt_vault(data, "correct")
        with self.assertRaises(InvalidTag):
            decrypt_vault(envelope,"wrong")

    def test_different_salts_each_time(self):
        data = {"entries": {}}
        e1 = encrypt_vault(data, "pw")
        e2 = encrypt_vault(data, "pw")
        self.assertNotEqual(e1["salt"],       e2["salt"])
        self.assertNotEqual(e1["nonce"],      e2["nonce"])
        self.assertNotEqual(e1["ciphertext"], e2["ciphertext"])

    def test_tampered_ciphertext_raises(self):
        import base64
        data = {"entries": {}}
        env = encrypt_vault(data, "pw")
        ct = bytearray(base64.b64decode(env["ciphertext"]))
        ct[0] ^= 0xFF
        env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with self.assertRaises(InvalidTag):
            decrypt_vault(env, "pw")

    def test_malformed_envelope_raises(self):
        with self.assertRaises(ValueError):
            decrypt_vault({"bad": "data"}, "pw")