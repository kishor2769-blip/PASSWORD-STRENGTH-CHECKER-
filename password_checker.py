"""Password-strength analysis functions.

This module checks a password string locally. It does NOT connect to Wi-Fi,
scan networks, attempt logins, or test whether a router is vulnerable.
"""
import math
import re
from typing import Dict, List

# A short demonstration deny-list. This is not an exhaustive password database.
COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty",
    "qwerty123", "admin", "admin123", "letmein", "welcome",
    "iloveyou", "abc123", "111111", "000000"
}

SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def _has_sequence(password: str, run_length: int = 4) -> bool:
    """Return True when a 4+ character ascending keyboard/alphanumeric run exists."""
    candidate = password.lower()
    for sequence in SEQUENCES:
        for index in range(len(sequence) - run_length + 1):
            run = sequence[index:index + run_length]
            if run in candidate:
                return True
    return False


def analyze_password(password: str) -> Dict[str, object]:
    """Return a transparent strength assessment without retaining the input."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    categories = {
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digits": any(char.isdigit() for char in password),
        "symbols": any(not char.isalnum() and not char.isspace() for char in password),
        "spaces": any(char.isspace() for char in password),
    }
    active_categories = sum(
        categories[key] for key in ("lowercase", "uppercase", "digits", "symbols")
    )

    # A simple estimate, not a guarantee of real-world crack time.
    pool_size = 0
    if categories["lowercase"]:
        pool_size += 26
    if categories["uppercase"]:
        pool_size += 26
    if categories["digits"]:
        pool_size += 10
    if categories["symbols"]:
        pool_size += 33
    entropy_bits = round(length * math.log2(pool_size), 1) if pool_size and length else 0.0

    issues: List[str] = []
    suggestions: List[str] = []
    normalized = password.lower()

    if length == 0:
        issues.append("No password was entered.")
        suggestions.append("Enter a sample passphrase to assess.")
    if length < 12:
        issues.append("Shorter than the recommended 12 characters.")
        suggestions.append("Use at least 12 characters; 16 or more is preferable.")
    if active_categories < 3:
        issues.append("Uses fewer than three character categories.")
        suggestions.append("Mix uppercase, lowercase, numbers, and symbols where practical.")
    if normalized in COMMON_PASSWORDS:
        issues.append("Matches a common or easily guessed password.")
        suggestions.append("Avoid common words, default credentials, and predictable phrases.")
    if len(set(password)) <= 2 and length >= 4:
        issues.append("Contains very little character variety.")
        suggestions.append("Avoid repeating the same one or two characters.")
    if re.search(r"(.)\1{3,}", password):
        issues.append("Contains a character repeated four or more times.")
        suggestions.append("Avoid long repeated-character patterns.")
    if _has_sequence(password):
        issues.append("Contains a predictable keyboard or character sequence.")
        suggestions.append("Avoid sequences such as 1234, abcd, or qwer.")
    if password and password.strip() != password:
        issues.append("Contains leading or trailing whitespace.")
        suggestions.append("Remove accidental spaces at the beginning or end.")

    # Score is a learning aid, not a cryptographic guarantee.
    score = 0
    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if length >= 16:
        score += 10
    score += active_categories * 10
    if entropy_bits >= 60:
        score += 10
    if entropy_bits >= 80:
        score += 10
    if normalized in COMMON_PASSWORDS:
        score -= 35
    if len(set(password)) <= 2 and length >= 4:
        score -= 15
    if re.search(r"(.)\1{3,}", password):
        score -= 10
    if _has_sequence(password):
        score -= 10
    score = max(0, min(100, score))

    if score >= 75 and length >= 12 and not issues:
        strength = "Strong"
    elif score >= 45:
        strength = "Moderate"
    else:
        strength = "Weak"

    if not suggestions:
        suggestions.append("Good result. Keep it unique and enable router security features such as WPA2-AES or WPA3.")
    return {
        "length": length,
        "categories": categories,
        "active_categories": active_categories,
        "estimated_entropy_bits": entropy_bits,
        "score": score,
        "strength": strength,
        "issues": issues,
        "suggestions": suggestions,
    }


def print_report(result: Dict[str, object]) -> None:
    """Print a readable report; the original password is never included."""
    print("\n" + "-" * 62)
    print("                 PASSWORD AUDIT REPORT")
    print("-" * 62)
    print(f"Length                 : {result['length']} characters")
    print(f"Character categories   : {result['active_categories']} / 4")
    print(f"Estimated entropy      : {result['estimated_entropy_bits']} bits (rough estimate)")
    print(f"Security score         : {result['score']} / 100")
    print(f"Strength               : {result['strength']}")
    print("\nChecks:")
    for name, passed in result["categories"].items():
        print(f"  [{'x' if passed else ' '}] {name.title()}")
    print("\nFindings:")
    if result["issues"]:
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("  - No basic weakness patterns detected.")
    print("\nRecommendations:")
    for suggestion in result["suggestions"]:
        print(f"  - {suggestion}")
    print("-" * 62)
