# CryptCheck 🛡️

A lightweight cybersecurity CLI tool to evaluate local password complexity against **IAM policies** and check for breach exposures using **k-Anonymity** with the _Have I Been Pwned_ API.

---

## Features

- **IAM Policy Complexity Analysis**: Audits length, uppercase, lowercase, numbers, and symbols.
- **k-Anonymity Privacy Guarantee**: Your full password and full hash **never leave your machine**. Only the first 5 characters of the SHA-1 hash are queried against the breach API.
- **Shoulder-Surfing Protection**: Uses secure hidden terminal input (`getpass`) so credentials aren't visible on the screen.
- **Instant Audit Report**: Shows risk rating and exact breach counts if compromised.

---

## Installation

Install directly from PyPI via `pip`:

```bash
pip install cryptcheck
```
