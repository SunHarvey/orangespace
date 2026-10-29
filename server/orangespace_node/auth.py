from collections import deque
from dataclasses import dataclass
import hashlib
import re
import secrets
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select

from .database import AccessSession, Database, User


PASSWORDS = PasswordHasher()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
USERNAME = re.compile(r"[a-z0-9][a-z0-9_.-]{2,63}\Z", re.ASCII)


def normalize_username(value: str) -> str:
    normalized = value.strip().lower()
    if not USERNAME.fullmatch(normalized):
        raise ValueError("username must be 3–64 ASCII letters, digits, _, . or -")
    return normalized


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_user(db: Database, username: str, password: str) -> User:
    username = normalize_username(username)
    if not 12 <= len(password) <= 1024:
        raise ValueError("password must contain 12–1024 characters")
    user = User(username=username, password_hash=PASSWORDS.hash(password))
    with db.session() as session:
        session.add(user)
        session.flush()
    return user


@dataclass(frozen=True)
class Identity:
    user_id: str
    username: str
    token_digest: str


class LoginLimiter:
    """Bounded per-process limiter; ingress must enforce a shared limit across workers."""
    def __init__(self, attempts: int, window: int):
        self.attempts = attempts
        self.window = window
        self.entries: dict[str, deque[float]] = {}
        self.lock = threading.Lock()

    def consume(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            # Keep memory bounded even when an attacker rotates source addresses.
            for old_key in list(self.entries):
                values = self.entries[old_key]
                while values and values[0] <= now - self.window:
                    values.popleft()
                if not values:
                    del self.entries[old_key]
            values = self.entries.get(key)
            if values is None:
                if len(self.entries) >= 10000:
                    return False
                values = self.entries[key] = deque()
            if len(values) >= self.attempts:
                return False
            values.append(now)
            return True


def login(db: Database, username: str, password: str, lifetime: int) -> tuple[str, int] | None:
    try:
        normalized = normalize_username(username)
    except ValueError:
        normalized = ""  # Still verify the dummy hash for unknown users.
    with db.session() as session:
        user = session.scalar(select(User).where(User.username == normalized))
        try:
            valid = PASSWORDS.verify(user.password_hash if user else DUMMY_HASH, password)
        except (VerificationError, InvalidHashError):
            valid = False
        if not valid or user is None or not user.enabled:
            return None
        if PASSWORDS.check_needs_rehash(user.password_hash):
            user.password_hash = PASSWORDS.hash(password)
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + lifetime
        session.add(AccessSession(token_digest=digest_token(token), user_id=user.id, expires_at=expires))
    return token, expires


def authenticate(db: Database, token: str) -> Identity | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token, re.ASCII):
        return None
    digest = digest_token(token)
    with db.session() as session:
        access = session.get(AccessSession, digest)
        if access is None or access.revoked_at is not None or access.expires_at <= int(time.time()):
            return None
        user = session.get(User, access.user_id)
        if user is None or not user.enabled:
            return None
        return Identity(user.id, user.username, digest)


def revoke(db: Database, digest: str) -> None:
    with db.session() as session:
        access = session.get(AccessSession, digest)
        if access:
            access.revoked_at = int(time.time())
