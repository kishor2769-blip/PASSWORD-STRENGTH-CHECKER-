# Wi-Fi Password Security Auditor

**CODTECH Internship – Technical/Coding Project**

| Field | Details |
|---|---|
| Intern ID | CIS30 |
| Full Name | Morcha shanmukha kishor |
| No. of Weeks | 4 |
| Project Name | Wi-Fi Password Security Auditor |
| Project Type | Python command-line security utility |

## 1. Project scope

This project performs a **local password-strength assessment** for a sample Wi-Fi passphrase. It checks length, character variety, common-password matches, repeated characters, and predictable keyboard/alphanumeric sequences. It produces a score, a strength label, findings, and recommendations.

**Important scope limitation:** This is a password-quality checker. It does not connect to a router, discover nearby Wi-Fi networks, capture traffic, attempt logins, or prove that a wireless network is secure. Router configuration (WPA2-AES/WPA3, firmware, WPS, guest network settings, etc.) must be reviewed separately.

## 2. Features

- Hidden terminal input using Python's `getpass`.
- Length and character-category checks.
- Small built-in list of common passwords.
- Detection of repeated-character and simple sequence patterns.
- Transparent heuristic score and rough entropy estimate.
- Actionable recommendations.
- Unit tests using Python's standard library.
- No password storage, network transmission, or logging.

## 3. Requirements

- Python 3.9 or later.
- No external Python packages are required.

## 4. Project structure

```text
WiFi-Password-Security-Auditor/
├── main.py
├── password_checker.py
├── test_password_checker.py
├── requirements.txt
├── README.md
├── .gitignore
├── screenshots/
│   └── sample_output.png
└── documentation/
    └── project_report.md
```

## 5. How to run

Open a terminal in this project folder:

```bash
python main.py
```

Enter a **sample password only** when prompted. The input is hidden.

Run tests:

```bash
python -m unittest -v
```

## 6. Example result

A sample run is shown in `screenshots/sample_output.png`. The original password is intentionally not shown in the report.

## 7. Methodology

1. Read a sample password through hidden terminal input.
2. Calculate its length and identify character categories.
3. Check for common values, repeated characters, and simple sequences.
4. Estimate a score and classify it as Weak, Moderate, or Strong.
5. Print findings and improvement suggestions.
6. Discard the input when the program exits.

## 8. Security and privacy

- Do not enter a password currently used for a real account or Wi-Fi network in a demonstration.
- The program does not save or transmit the entered value.
- The score and entropy are educational estimates, not a guarantee of resistance to cracking.
- Use a unique passphrase and a password manager. For a real router, prefer WPA3-Personal or WPA2-AES, update firmware, disable WPS if not needed, and use a unique administrator password.

## 9. Test cases

| Test | Expected result |
|---|---|
| Empty input | Weak; empty-input finding |
| `password123` | Common-password warning |
| `abc123` | Weak score compared with long mixed sample |
| Long mixed sample | Higher score than short weak sample |
| Non-string input | Raises `TypeError` |

## 10. Author

**Morcha shanmukha kishor**  
CODTECH Intern ID: **CIS30**  
Internship duration: **4 weeks**
