#!/usr/bin/env python3
"""
pypassman - A secure command-line password manager.

Commands:
  init          Create a new vault
  add           Add a new entry
  get           Retrieve credentials for an entry
  list          List all entries
  search        Search entries
  edit          Update an entry
  delete        Delete an entry
  generate      Generate a secure password
  passwd        Change the master password
"""

import sys
import getpass
import argparse
from pathlib import Path

from vault import Vault, VaultError, WrongPasswordError, DEFAULT_VAULT_PATH
from password_gen import generate_password, password_strength


# ---------------------------------------------------------------------------
# ANSI colors (auto-disabled on non-TTY)
# ---------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):  return _c("32", t)
def red(t):    return _c("31", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_master_password(prompt="Master password: ") -> str:
    pw = getpass.getpass(prompt)
    if not pw:
        print(red("Error: Master password cannot be empty."))
        sys.exit(1)
    return pw