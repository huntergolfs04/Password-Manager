"""
password_gen.py - Cryptographically secure password generator.

Uses secrets module (backed by os.urandom) - never random.
"""

import secrets
import string

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS    = string.digits
SYMBOLS   = "!@#$%^&*()-_=+[]{}|;:,.<>?"

def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    generates a cryptographically secure random password

    args:
        length:            total character count (min 8)
        use_upper:         include A-Z
        use_lower:         include a-z
        use_digits:        include 0-9
        use_symbols:       include special characters
        exclude_ambiguous: remove visually similar chars (0, O, l, 1, I)

    returns:
        a random password string guaranteed to contain at least one
        character from each enabled character class
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    pools = []
    if use_upper:   pools.append(UPPERCASE)
    if use_lower:   pools.append(LOWERCASE)
    if use_digits:  pools.append(DIGITS)
    if use_symbols: pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    if exclude_ambiguous:
        ambiguous = set("0Ol1I")
        pools = ["".join(c for c in pool if c not in ambiguous) for pool in pools]

    alphabet = "".join(pools)

    while True:
        password_chars = [secrets.choice(pool) for pool in pools]
        remaining = length - len(password_chars)
        password_chars += [secrets.choice(alphabet) for _ in range(remaining)]
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)

        if all(any(c in pool for c in password) for pool in pools):
            return password
        
def password_strength(password: str) -> dict:
    """
    estimates password strength; returns a dict with score and feedback.
    score: 0 (very weak) → 4 (very strong)
    """
    score = 0
    feedback = []

    if len(password) >= 12: score += 1
    else: feedback.append("Use at least 12 characters")

    if len(password) >= 20: score += 1

    has_upper  = any(c in UPPERCASE for c in password)
    has_lower  = any(c in LOWERCASE for c in password)
    has_digit  = any(c in DIGITS    for c in password)
    has_symbol = any(c in SYMBOLS   for c in password)

    classes = sum([has_upper, has_lower, has_digit, has_symbol])
    if classes >= 3: score += 1
    if classes == 4: score += 1

    if not has_upper:  feedback.append("Add uppercase letters")
    if not has_lower:  feedback.append("Add lowercase letters")
    if not has_digit:  feedback.append("Add digits")
    if not has_symbol: feedback.append("Add special characters")

    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return {
        "score":    score,
        "labels":   labels[min(score, 4)],
        "feedback": feedback,
    }
