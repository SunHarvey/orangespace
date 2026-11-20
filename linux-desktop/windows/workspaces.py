"""Local accounts and per-account desktop inventory for the Windows developer build."""
import hashlib
import hmac
import os
import sqlite3
import unicodedata
import uuid
from contextlib import closing


def identity(value):
    value = unicodedata.normalize("NFC", value.strip()).casefold()
    if not 1 <= len(value) <= 80 or any(not char.isprintable() for char in value):
        raise ValueError("账号长度须为 1–80 个可打印字符")
    return value


def label(value):
    value = value.strip()
    if not 1 <= len(value) <= 80 or not value.isprintable():
        raise ValueError("名称长度须为 1–80 个可打印字符")
    return value


def canonical(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("UUID 格式错误")
    return value


def password_hash(password, salt):
    encoded = password.encode("utf-8")
    if len(encoded) > 1024:
        raise ValueError("密码过长")
    return hashlib.scrypt(encoded, salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024**2)


class Store:
    def __init__(self, path):
        self.path = path
        with closing(self.connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS account (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, salt BLOB NOT NULL, hash BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sandbox (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES account(id),
                    name TEXT NOT NULL, node TEXT NOT NULL, UNIQUE(user_id, name)
                );
            """)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys=ON")
        db.row_factory = sqlite3.Row
        return db

    def register(self, name, password):
        name = identity(name)
        if len(password) < 12:
            raise ValueError("密码至少 12 个字符")
        salt = os.urandom(16)
        digest = password_hash(password, salt)
        user = str(uuid.uuid4())
        try:
            with closing(self.connect()) as db, db:
                db.execute("INSERT INTO account VALUES (?,?,?,?)", (user, name, salt, digest))
        except sqlite3.IntegrityError:
            raise ValueError("账号已存在") from None
        return user

    def login(self, name, password):
        with closing(self.connect()) as db:
            row = db.execute("SELECT * FROM account WHERE name=?", (identity(name),)).fetchone()
        salt = row["salt"] if row else bytes(16)
        digest = password_hash(password, salt)
        if not hmac.compare_digest(digest, row["hash"] if row else bytes(32)) or row is None:
            raise ValueError("账号或密码错误")
        return row["id"]

    def list(self, user):
        with closing(self.connect()) as db:
            return [dict(row) for row in db.execute("SELECT * FROM sandbox WHERE user_id=? ORDER BY name", (user,))]

    def create(self, user, name, node):
        sandbox = str(uuid.uuid4())
        try:
            with closing(self.connect()) as db, db:
                db.execute("INSERT INTO sandbox VALUES (?,?,?,?)", (sandbox, user, label(name), canonical(node)))
        except sqlite3.IntegrityError:
            raise ValueError("不能创建沙盒，请检查账号和名称") from None
        return sandbox

    def bind(self, user, sandbox, node):
        with closing(self.connect()) as db, db:
            changed = db.execute("UPDATE sandbox SET node=? WHERE user_id=? AND id=?",
                                 (canonical(node), user, sandbox)).rowcount
            if changed != 1:
                raise ValueError("找不到当前账号的沙盒")
