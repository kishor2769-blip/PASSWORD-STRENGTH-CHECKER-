"""Command-line interface for the Wi-Fi Password Security Auditor.

Privacy note: the password is entered with getpass (hidden input), is analyzed
in memory only, and is never saved, printed, transmitted, or logged.
"""
from getpass import getpass
from password_checker import analyze_password, print_report


def main():
    print("=" * 62)
    print("          WI-FI PASSWORD SECURITY AUDITOR")
    print("=" * 62)
    print("Local password-strength assessment only.")
    print("Do not enter a password that you currently use.")
    print("Use a sample password for this demonstration.\n")

    password = getpass("Enter a SAMPLE password (input hidden): ")
    result = analyze_password(password)
    print_report(result)

    print("\nPrivacy: your input was not stored or sent anywhere.")


if __name__ == "__main__":
    main()
