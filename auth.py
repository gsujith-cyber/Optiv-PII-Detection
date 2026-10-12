
"""Authentication module for the PII Detection application."""

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

import bcrypt

# Keep paths relative to this file, not the current working directory.
BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
LOG_FILE = BASE_DIR / "data" / "access_log.csv"


def _load() -> dict:
    """Load usernames and bcrypt password hashes."""
    if not USERS_FILE.exists():
        return {}

    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def add_user(username: str, password: str) -> None:
    """Create or update a user with a bcrypt password hash."""
    if not username or not password:
        raise ValueError("Username and password cannot be empty.")

    users = _load()
    users[username] = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    USERS_FILE.write_text(
        json.dumps(users, indent=2),
        encoding="utf-8"
    )


def verify_login(username: str, password: str) -> bool:
    """Return True only when the username and password match."""
    if not username or not password:
        return False

    stored_hash = _load().get(username)

    if not isinstance(stored_hash, str):
        return False

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def log_event(user: str, action: str, detail: str = "") -> None:
    """Record access events without storing passwords."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    new_file = not LOG_FILE.exists()

    def clean(value):
        value = str(value)
        if value[:1] in ("=", "+", "-", "@"):
            return "'" + value
        return value

    with LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow(["time", "user", "action", "detail"])

        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            clean(user),
            clean(action),
            clean(detail),
        ])


def read_log(n: int = 10) -> list:
    """Return the newest access events first."""
    if not LOG_FILE.exists():
        return []

    with LOG_FILE.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    return rows[-max(0, n):][::-1] if n > 0 else []


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "add":
        add_user(sys.argv[2], sys.argv[3])
        print(f"User '{sys.argv[2]}' saved successfully.")
    else:
        print("Usage: python auth.py add <username> <password>")
