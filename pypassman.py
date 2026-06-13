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

def _confirm_password(prompt="Master password: ") -> str:
    pw = _get_master_password(prompt)
    confirm = getpass.getpass("Confirm master password: ")
    if pw != confirm:
        print(red("Error: Passwords do not match."))
        sys.exit(1)
    return pw

def _print_entry(entry: dict, show_password: bool = False) -> None:
    print()
    print(bold(f"  {entry['site']}"))
    print(f"  {'ID:':<12} {dim(entry['id'])}")
    print(f"  {'Username:':<12} {entry['username']}")
    if show_password:
        print(f"  {'Password:':<12} {yellow(entry['password'])}")
    else:
        print(f"  {'Password:':<12} {dim('(hidden — use get --show to reveal)')}")
    if entry.get("notes"):
        print(f"  {'Notes:':<12} {entry['notes']}")
    print(f"  {'Updated:':<12} {dim(entry.get('updated', ''))}")
    print()

def _print_separator():
    print(dim("-" * 60))

def _select_entry(vault: Vault, query: str) -> dict:
    """finds entry by ID prefix or by site search"""
    entries = vault.list_entries()

    matches = [e for e in entries if e["id"].startswith(query)]

    if not matches:
        matches = vault.search(query)

    if not matches:
        print(red(f"No entries found matching: '{query}'"))
        sys.exit(1)

    if len(matches) == 1:
        return vault.get_entry(matches[0]["id"])
    
    print(yellow(f"Multiple entries found for '{query}':"))
    for i, e in enumerate(matches, 1):
        print(f"  [{i}] {e['site']} ({e['username']})  {dim(e['id'][:8]+'...')}")
    choice = input("Select [1]: ").strip() or "1"
    try:
        idx = int(choice) - 1
        return vault.get_entry(matches[idx]["id"])
    except (ValueError, IndexError):
        print(red("Invalid selection."))
        sys.exit(1)

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args, vault: Vault):
    print(bold("Creating a new vault..."))
    print(yellow("Choose a strong master password. There is NO recovery if you forget it."))
    password = _confirm_password()
    try:
        vault.create(password)
        print(green(f"✓ Vault created at {vault.vault_path}"))
    except VaultError as e:
        print(red(f"Error: {e}"))
        sys.exit(1)

def cmd_add(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)

    print(bold("\nAdd new entry"))
    site     = input("Site/Service: ").strip()
    username = input("Username/Email: ").strip()

    if not site or not username:
        print(red("Site and username are required."))
        sys.exit(1)

    gen = input("Generate a password? [Y/n]: ").strip().lower()
    if gen in ("", "y", "yes"):
        length_str = input("Password length [20]: ").strip() or "20"
        try:
            length = int(length_str)
        except ValueError:
            length = 20
        pw = generate_password(length=length)
        print(f"Generated: {yellow(pw)}")
        strength = password_strength(pw)
        print(f"Strength:  {green(strength['label'])}")
    else:
        pw = getpass.getpass("Password: ")
        confirm_pw = getpass.getpass("Confirm password: ")
        if pw != confirm_pw:
            print(red("Passwords do not match."))
            sys.exit(1)
        strength = password_strength(pw)
        print(f"Strength:  {_strength_color(strength)(strength['label'])}", end="")
        if strength["feedback"]:
            print(f"  {dim('— ' + ', '.join(strength['feedback']))}", end="")
        print()

    notes = input("Notes (optional): ").strip()
    entry_id = vault.add_entry(site, username, pw, notes)
    print(green(f"\n✓ Entry saved (ID: {entry_id[:8]}...)"))
    vault.lock()

def _strength_color(strength: dict):
    return [red, red, yellow, green, green][min(strength["score"], 4)]

def cmd_get(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)
    entry = _select_entry(vault, args.query)
    _print_entry(entry, show_password=args.show)
    vault.lock()

def cmd_list(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)
    entries = vault.list_entries()
    if not entries:
        print(yellow("Vault is empty. Use 'add' to create your first entry."))
        vault.lock()
        return
    print(bold(f"\n  {vault.entry_count()} entries in vault\n"))
    _print_separator()
    for e in entries:
        print(f"  {bold(e['site'][:30]):<32} {e['username'][:28]:<30} {dim(e['id'][:8]+'...')}")
    _print_separator()
    print()
    vault.lock()

def cmd_search(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)
    results = vault.search(args.query)
    if not results:
        print(yellow(f"No entries found matching '{args.query}'."))
    else:
        print(bold(f"\n  Found {len(results)} result(s) for '{args.query}'\n"))
        _print_separator()
        for e in results:
            print(f"  {bold(e['site'][:30]):<32} {e['username'][:28]:<30} {dim(e['id'][:8]+'...')}")
        _print_separator()
        print()
    vault.lock()

def cmd_edit(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)
    entry = _select_entry(vault, args.query)
    print(bold(f"\nEditing: {entry['site']} ({entry['username']})"))
    print(dim("Press Enter to keep current value.\n"))

    updates = {}
    new_site = input(f"Site [{entry['site']}]: ").strip()
    if new_site: updates["site"] = new_site

    new_user = input(f"Username [{entry['username']}]: ").strip()
    if new_user: updates["username"] = new_user

    change_pw = input("Change password? [y/N]: ").strip().lower()
    if change_pw in ("y", "yes"):
        gen = input("Generate new password? [Y/n]: ").strip().lower()
        if gen in ("", "y", "yes"):
            length_str = input("Length [20]: ").strip() or "20"
            new_pw = generate_password(length=int(length_str))
            print(f"Generated: {yellow(new_pw)}")
        else:
            new_pw = getpass.getpass("New password: ")
        updates["password"] = new_pw

    new_notes = input(f"Notes [{entry.get('notes','')}]: ").strip()
    if new_notes: updates["notes"] = new_notes

    if updates:
        vault.update_entry(entry["id"], **updates)
        print(green("\n✓ Entry updated."))
    else:
        print(dim("\nNo changes made."))
    vault.lock()

def cmd_delete(args, vault: Vault):
    password = _get_master_password()
    vault.unlock(password)
    entry = _select_entry(vault, args.query)
    print(bold(f"\nDelete entry: {entry['site']} ({entry['username']})"))
    confirm = input(red("Type 'DELETE' to confirm: ")).strip()
    if confirm == "DELETE":
        vault.delete_entry(entry["id"])
        print(green("Entry deleted."))
    else:
        print(dim("Cancelled."))
    vault.lock()

def cmd_generate(args):
    pw = generate_password(
        length=args.length,
        use_upper=not args.no_upper,
        use_lower=not args.no_lower,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        exclude_ambiguous=args.no_ambiguous,
    )
    strength = password_strength(pw)
    color = _strength_color(strength)
    print(f"\n  {bold('Password:')} {yellow(pw)}")
    print(f"  {bold('Strength:')} {color(strength['label'])}")
    if strength["feedback"]:
        print(f"  {bold('Tips:')}")
        for tip in strength["feedback"]:
            print(f"    • {tip}")
    print()

def cmd_passwd(args, vault: Vault):
    print(bold("Change master password"))
    old_pw = _get_master_password("Current master password: ")
    vault.unlock(old_pw)
    new_pw = _confirm_password("New master password: ")
    vault.change_password(old_pw, new_pw)
    print(green("Master password changed successfully."))
    vault.lock()

# ---------------------------------------------------------------------------
# Argument parser & entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pypassman",
        description="pypassman - secure CLI password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--vault", metavar="PATH", default=str(DEFAULT_VAULT_PATH),
        help=f"Path to vault file (default: {DEFAULT_VAULT_PATH})"
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("init",   help="Create a new vault")
    sub.add_parser("add",    help="Add a new entry")
    sub.add_parser("list",   help="List all entries")
    sub.add_parser("passwd", help="Change the master password")

    get_p = sub.add_parser("get", help="Retrieve an entry")
    get_p.add_argument("query")
    get_p.add_argument("--show", action="store_true", help="Show password in plaintext")

    search_p = sub.add_parser("search", help="Search entries")
    search_p.add_argument("query")

    edit_p = sub.add_parser("edit", help="Edit an entry")
    edit_p.add_argument("query")

    del_p = sub.add_parser("delete", help="Delete an entry")
    del_p.add_argument("query")

    gen_p = sub.add_parser("generate", help="Generate a secure password")
    gen_p.add_argument("-l", "--length", type=int, default=20)
    gen_p.add_argument("--no-upper",      action="store_true")
    gen_p.add_argument("--no-lower",      action="store_true")
    gen_p.add_argument("--no-digits",     action="store_true")
    gen_p.add_argument("--no-symbols",    action="store_true")
    gen_p.add_argument("--no-ambiguous",  action="store_true")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    vault = Vault(vault_path=Path(args.vault))

    try:
        if   args.command == "init":     cmd_init(args, vault)
        elif args.command == "add":      cmd_add(args, vault)
        elif args.command == "get":      cmd_get(args, vault)
        elif args.command == "list":     cmd_list(args, vault)
        elif args.command == "search":   cmd_search(args, vault)
        elif args.command == "edit":     cmd_edit(args, vault)
        elif args.command == "delete":   cmd_delete(args, vault)
        elif args.command == "generate": cmd_generate(args)
        elif args.command == "passwd":   cmd_passwd(args, vault)

    except WrongPasswordError as e:
        print(red(f"\nX {e}"))
        sys.exit(1)
    except VaultError as e:
        print(red(f"\nX {e}"))
        sys.exit(1)
    except KeyboardInterrupt:
        print(dim("\nAborted."))
        sys.exit(0)


if __name__ == "__main__":
    main()
