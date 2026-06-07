# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public issue**.
Instead, report it privately by emailing: hunterh2023@icloud.com

You can expect a response within 7 days. I will keep you updated as I
investigate and work on a fix. If the vulnerability is confirmed, I will
patch it and credit you in the release notes (unless you prefer to remain
anonymous).

## Security Considerations

This project uses:
- **AES-256-GCM** for vault encryption
- **scrypt** (N=2¹⁷) for master password key derivation
- **Python's `secrets` module** for cryptographically secure password generation

Known limitations:
- The vault is only as secure as your master password — use a strong one
- No memory locking is implemented; decrypted data lives in Python's heap
- No clipboard auto-clear when copying passwords
- No account recovery — a forgotten master password means permanent data loss
