"""auth.py (Member 4) - username/password login for viewing the ORIGINAL file.
Users live in users.json (bcrypt hashes only). Add a user from the terminal:
    python auth.py add admin MyPassword123
"""
import json
import sys
from pathlib import Path

import bcrypt

USERS_FILE = Path("users.json")


def _load() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return {}


def add_user(username: str, password: str) -> None:
    users = _load()
    users[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    USERS_FILE.write_text(json.dumps(users, indent=2))


def verify_login(username: str, password: str) -> bool:
    stored = _load().get(username)
    if not stored:
        return False
    return bcrypt.checkpw(password.encode(), stored.encode())


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "add":
        add_user(sys.argv[2], sys.argv[3])
        print(f"User '{sys.argv[2]}' saved to {USERS_FILE}")
    else:
        print("Usage: python auth.py add <username> <password>")