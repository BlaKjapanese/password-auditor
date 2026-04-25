# Password Auditor

A command-line password auditing tool built in Python for cybersecurity learning purposes.
Tests password strength and simulates real-world cracking techniques used by security professionals.

## Features

- **Strength checker** — scores passwords 1-5 with improvement tips
- **Dictionary attack** — tests hashes against the rockyou.txt wordlist (14M passwords)
- **Brute force** — tries every combination up to a specified length
- **bcrypt support** — demonstrates why modern hashing algorithms resist cracking
- **Hash generator** — generates MD5, SHA-1, SHA-256, and bcrypt hashes

## Requirements

- Python 3
- Kali Linux (or any Linux with rockyou.txt)
- bcrypt library

```bash
pip install bcrypt
```

## Usage

```bash
# Check password strength
python3 auditor.py --mode strength --password "Hello123!"

# Generate a hash
python3 auditor.py --mode hash --password "sunshine" --algorithm md5

# Dictionary attack
python3 auditor.py --mode dictionary --hash <hash> --algorithm md5

# Brute force (digits, up to 4 characters)
python3 auditor.py --mode brute --hash <hash> --charset digits --max-length 4

# Crack a bcrypt hash
python3 auditor.py --mode bcrypt --hash <hash>
```

## What I learned

- How MD5, SHA-1, SHA-256, and bcrypt hashing algorithms work
- Why bcrypt is the industry standard for password storage (intentionally slow + salted)
- How dictionary attacks exploit common passwords using real-world leaked wordlists
- How brute force attacks work and why password length matters exponentially
- Python file I/O, hashlib, argparse, itertools, and bcrypt libraries

## Legal disclaimer

This tool is for educational purposes only. Only use it on systems and hashes you own
or have explicit permission to test.
