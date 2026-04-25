#!/usr/bin/env python3
import hashlib
import bcrypt
import itertools
import string
import argparse
import sys
import time
import re

def hash_password(password, algorithm="sha256"):
    password = password.strip()
    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        print(f"[ERROR] Unknown algorithm: {algorithm}")
        sys.exit(1)

def hash_bcrypt(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def check_strength(password):
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 8 characters")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter")
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add at least one number")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add at least one special character")
    labels = ["Very weak", "Weak", "Moderate", "Strong", "Very strong"]
    bars   = ["█░░░░", "██░░░", "███░░", "████░", "█████"]
    print(f"\n  Password : {password}")
    print(f"  Strength : {bars[score-1]}  {labels[score-1]} ({score}/5)")
    if feedback:
        print("\n  Tips:")
        for tip in feedback:
            print(f"    - {tip}")
    else:
        print("\n  No suggestions — solid password!")

def dictionary_attack(target_hash, wordlist_path, algorithm="sha256"):
    print(f"\n  Algorithm : {algorithm.upper()}")
    print(f"  Wordlist  : {wordlist_path}")
    print(f"  Target    : {target_hash}\n")
    start = time.time()
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for count, line in enumerate(f, start=1):
                word = line.strip()
                attempt = hash_password(word, algorithm)
                if count % 500000 == 0:
                    elapsed = time.time() - start
                    print(f"  {count:,} attempts — {elapsed:.1f}s elapsed...")
                if attempt == target_hash:
                    elapsed = time.time() - start
                    print(f"\n  [CRACKED]  {word}")
                    print(f"  Attempts : {count:,}")
                    print(f"  Time     : {elapsed:.2f}s")
                    return word
    except FileNotFoundError:
        print(f"  [ERROR] Wordlist not found: {wordlist_path}")
        sys.exit(1)
    print(f"\n  [FAILED] Password not found in wordlist")
    return None

def brute_force(target_hash, algorithm="sha256", max_length=4, charset="lowercase"):
    charsets = {
        "lowercase":    string.ascii_lowercase,
        "digits":       string.digits,
        "alphanumeric": string.ascii_lowercase + string.digits,
        "full":         string.ascii_letters + string.digits + string.punctuation,
    }
    chars = charsets.get(charset, charset)
    print(f"\n  Algorithm : {algorithm.upper()}")
    print(f"  Charset   : {charset} ({len(chars)} chars)")
    print(f"  Max length: {max_length}")
    print(f"  Target    : {target_hash}\n")
    total = 0
    start = time.time()
    for length in range(1, max_length + 1):
        print(f"  Trying length {length}...")
        for combo in itertools.product(chars, repeat=length):
            word = "".join(combo)
            attempt = hash_password(word, algorithm)
            total += 1
            if attempt == target_hash:
                elapsed = time.time() - start
                print(f"\n  [CRACKED]  {word}")
                print(f"  Attempts : {total:,}")
                print(f"  Time     : {elapsed:.2f}s")
                return word
    elapsed = time.time() - start
    print(f"\n  [FAILED] Not found. Attempts: {total:,} | Time: {elapsed:.2f}s")
    return None

def crack_bcrypt(target_hash, wordlist_path):
    print(f"\n  Wordlist : {wordlist_path}")
    print(f"  Target   : {target_hash}\n")
    print("  bcrypt is slow by design — be patient.\n")
    start = time.time()
    count = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for count, line in enumerate(f, start=1):
                word = line.strip().encode("utf-8")
                if bcrypt.checkpw(word, target_hash.encode("utf-8")):
                    elapsed = time.time() - start
                    print(f"\n  [CRACKED]  {word.decode()}")
                    print(f"  Attempts : {count:,}")
                    print(f"  Time     : {elapsed:.2f}s")
                    return word.decode()
                if count % 10 == 0:
                    print(f"  Tried {count:,} passwords...", end="\r")
    except FileNotFoundError:
        print(f"  [ERROR] Wordlist not found: {wordlist_path}")
        sys.exit(1)
    print(f"\n  [FAILED] Not found after {count:,} attempts")
    return None

def main():
    parser = argparse.ArgumentParser(
        prog="auditor.py",
        description="Password Auditor — a cybersecurity learning tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--mode", required=True,
        choices=["strength", "dictionary", "brute", "bcrypt", "hash"])
    parser.add_argument("--password")
    parser.add_argument("--hash")
    parser.add_argument("--algorithm", default="sha256",
        choices=["md5", "sha1", "sha256"])
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    parser.add_argument("--max-length", type=int, default=4)
    parser.add_argument("--charset", default="lowercase",
        choices=["lowercase", "digits", "alphanumeric", "full"])
    args = parser.parse_args()
    print("\n" + "=" * 50)
    print(f"  Password Auditor | mode: {args.mode.upper()}")
    print("=" * 50)
    if args.mode == "strength":
        if not args.password:
            print("[ERROR] --password is required")
            sys.exit(1)
        check_strength(args.password)
    elif args.mode == "hash":
        if not args.password:
            print("[ERROR] --password is required")
            sys.exit(1)
        h = hash_password(args.password, args.algorithm)
        print(f"\n  Input : {args.password}")
        print(f"  Algo  : {args.algorithm.upper()}")
        print(f"  Hash  : {h}")
    elif args.mode == "dictionary":
        if not args.hash:
            print("[ERROR] --hash is required")
            sys.exit(1)
        dictionary_attack(args.hash, args.wordlist, args.algorithm)
    elif args.mode == "brute":
        if not args.hash:
            print("[ERROR] --hash is required")
            sys.exit(1)
        brute_force(args.hash, args.algorithm, args.max_length, args.charset)
    elif args.mode == "bcrypt":
        if not args.hash:
            print("[ERROR] --hash is required")
            sys.exit(1)
        crack_bcrypt(args.hash, args.wordlist)
    print("\n" + "=" * 50 + "\n")

if __name__ == "__main__":
    main()
