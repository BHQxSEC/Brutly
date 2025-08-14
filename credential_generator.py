import argparse
import base64
import csv
import hashlib
import json
import os
import re
import secrets
import string
import sys
import unicodedata
from typing import List, Dict, Optional, Set, Tuple


def make_password(length: int = 16, symbols: bool = True) -> str:
    """Generate a strong random password with the requested length and complexity."""
    if length < 8:
        raise ValueError("Password length should be at least 8.")
    letters = string.ascii_letters
    digits = string.digits
    punct = string.punctuation if symbols else ""
    alphabet = letters + digits + punct
    # Ensure at least one from each required class
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and (not symbols or any(c in punct for c in pwd))
        ):
            return pwd

def hash_pbkdf2(password: str, iterations: int = 200_000, salt: Optional[bytes] = None) -> str:
    """Return a Django-like PBKDF2-SHA256 string: pbkdf2_sha256$iters$salt_b64$hash_b64"""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def normalize_ascii(text: str) -> str:
    """Convert to lowercase ASCII, stripping accents."""
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()

def username_from_name(name: str, fmt: str = "first.last") -> str:
    name_ascii = normalize_ascii(name)
    words = re.findall(r"[a-z0-9]+", name_ascii)
    if not words:

        return f"user{secrets.randbelow(10_000):04}"
    first, *rest = words
    last = rest[-1] if rest else ""
    if fmt == "first.last":
        base = f"{first}.{last}" if last else first
    elif fmt == "f_last":
        base = (first[0] + "_" + last) if last else first
    elif fmt == "simple":
        base = "".join(words)
    elif fmt == "keep":
        base = re.sub(r"\s+", "", name_ascii)
    else:
        base = "".join(words)

    base = re.sub(r"[^a-z0-9._-]", "", base)
    base = base.strip("._-")
    return base or f"user{secrets.randbelow(10_000):04}"

def uniquify(base: str, taken: Set[str]) -> str:
    candidate = base
    i = 1
    while candidate in taken or not candidate:
        i += 1
        candidate = f"{base}{i}"
    taken.add(candidate)
    return candidate

def parse_names_from_file(path: str) -> List[Tuple[str, Optional[str]]]:
    """
    Reads lines like:
      Full Name
      Full Name, email@example.com
    Returns list of (name, email_or_none)
    """
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",", 1)]
            if len(parts) == 1:
                out.append((parts[0], None))
            else:
                out.append((parts[0], parts[1] or None))
    return out

def prompt_names_interactive() -> List[Tuple[str, Optional[str]]]:
    print("Enter full names, one per line. Optionally add ', email@example.com'.")
    print("Press Enter on a blank line when you're done.\n")
    items = []
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break
        if not line:
            break
        parts = [p.strip() for p in line.split(",", 1)]
        if len(parts) == 1:
            items.append((parts[0], None))
        else:
            items.append((parts[0], parts[1] or None))
    return items

def build_credentials(
    entries: List[Tuple[str, Optional[str]]],
    username_format: str = "first.last",
    email_domain: Optional[str] = None,
    pw_length: int = 16,
    use_symbols: bool = True,
    make_hash: bool = True,
) -> List[Dict[str, str]]:
    taken: Set[str] = set()
    rows: List[Dict[str, str]] = []
    for name, email in entries:
        base_user = username_from_name(name, username_format)
        user = uniquify(base_user, taken)
        if email is None and email_domain:
            email = f"{user}@{email_domain}"
        password = make_password(pw_length, use_symbols)
        password_hash = hash_pbkdf2(password) if make_hash else ""
        rows.append(
            {
                "name": name,
                "username": user,
                "email": email or "",
                "password": password,
                "password_hash": password_hash,
            }
        )
    return rows

def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    fieldnames = ["name", "username", "email", "password", "password_hash"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def write_json(rows: List[Dict[str, str]], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Easy credential generator")
    p.add_argument("--from-file", help="Path to a text file with names (one per line, optional ', email')")
    p.add_argument("--format", default="first.last", choices=["first.last", "f_last", "simple", "keep"], help="Username format")
    p.add_argument("--email-domain", help="If provided, set email to username@DOMAIN when email is missing")
    p.add_argument("--length", type=int, default=16, help="Password length (min 8)")
    p.add_argument("--no-symbols", action="store_true", help="Generate passwords without punctuation symbols")
    p.add_argument("--no-hash", action="store_true", help="Do not compute PBKDF2 password hashes")
    p.add_argument("--out", default="credentials.csv", help="Output path (.csv or .json)")
    args = p.parse_args(argv)
    if args.length < 8:
        print("Please choose --length >= 8", file=sys.stderr)
        return 2

    if args.from_file:
        if not os.path.exists(args.from_file):
            print(f"File not found: {args.from_file}", file=sys.stderr)
            return 2
        entries = parse_names_from_file(args.from_file)
    else:
        entries = prompt_names_interactive()
    if not entries:
        print("No names provided. Exiting.")
        return 0
    rows = build_credentials(
        entries=entries,
        username_format=args.format,
        email_domain=args.email_domain,
        pw_length=args.length,
        use_symbols=not args.no_symbols,
        make_hash=not args.no_hash,
    )
    out_path = args.out
    if out_path.lower().endswith(".json"):
        write_json(rows, out_path)
    else:
        if not out_path.lower().endswith(".csv"):
            out_path += ".csv"
        write_csv(rows, out_path)

    print(f"Saved {len(rows)} credential(s) to {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
