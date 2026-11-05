import argparse
import asyncio
import getpass
import json
import sys
import time

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .auth import PASSWORDS, create_user, normalize_username, set_tunnel_grant
from .config import Settings
from .database import AccessSession, Database, User
from .storage import PersonalStorage


def _publish_identity_evidence(args: argparse.Namespace) -> None:
    try:
        settings = Settings.from_env()
        db = Database(settings.database_url)
        try:
            db.initialize()
            from .control_identity import load_machine_config, submit_inventory

            machine = load_machine_config(args.machine_config)
            if machine["node_id"] != str(settings.node_id):
                raise ValueError("machine configuration belongs to another node")
            result = asyncio.run(submit_inventory(db.engine, machine, args.legacy_user_id, args.request_id))
            public = {key: result[key] for key in ("schema", "evidence_digest", "expires_at")}
            output = json.dumps(public, separators=(",", ":"))
        finally:
            db.close()
        print(output)
    except Exception:
        # Cover startup and shutdown too; never relay configuration/SQL secrets.
        print("Identity inventory submission failed.", file=sys.stderr)
        raise SystemExit(1) from None


def main() -> None:
    parser = argparse.ArgumentParser(description="OrangeSpace node administration; passwords are read privately")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    for command in ("create-user", "disable-user", "enable-user", "set-password", "revoke-sessions", "enable-tunnel", "disable-tunnel"):
        child = sub.add_parser(command)
        child.add_argument("username")
    sub.add_parser("list-users")
    cleanup = sub.add_parser("cleanup-uploads")
    cleanup.add_argument("--older-than-hours", type=int, default=24)
    inventory = sub.add_parser("publish-identity-evidence")
    inventory.add_argument("--machine-config", required=True)
    inventory.add_argument("--legacy-user-id", required=True)
    inventory.add_argument("--request-id", required=True)
    args = parser.parse_args()
    if args.command == "publish-identity-evidence":
        _publish_identity_evidence(args)
        return
    settings = Settings.from_env()
    db = Database(settings.database_url)
    try:
        db.initialize()
        if args.command == "init-db":
            storage = PersonalStorage(settings.data_root)
            storage.close()
            print("Database initialized; personal storage validated.")
        elif args.command == "cleanup-uploads":
            storage = PersonalStorage(settings.data_root)
            try:
                removed = storage.cleanup_uploads(args.older_than_hours * 3600)
            finally:
                storage.close()
            print(f"Removed {removed} abandoned upload staging files.")
        elif args.command == "create-user":
            password = getpass.getpass("Password (12–1024 characters): ")
            if password != getpass.getpass("Repeat password: "):
                parser.error("passwords do not match")
            user = create_user(db, args.username, password)
            print(f"Created {user.username} ({user.id})")
        elif args.command in ("enable-tunnel", "disable-tunnel"):
            set_tunnel_grant(db, args.username, args.command == "enable-tunnel")
            print("Tunnel grant updated.")
        elif args.command == "list-users":
            with db.session() as session:
                for user in session.scalars(select(User).order_by(User.username)):
                    print(f"{user.id}\t{user.username}\t{'enabled' if user.enabled else 'disabled'}")
        else:
            username = normalize_username(args.username)
            with db.session() as session:
                user = session.scalar(select(User).where(User.username == username))
                if user is None:
                    parser.error("user not found")
                if args.command == "disable-user":
                    user.enabled = False
                elif args.command == "enable-user":
                    user.enabled = True
                elif args.command == "set-password":
                    password = getpass.getpass("New password (12–1024 characters): ")
                    if not 12 <= len(password) <= 1024:
                        parser.error("password must contain 12–1024 characters")
                    if password != getpass.getpass("Repeat password: "):
                        parser.error("passwords do not match")
                    user.password_hash = PASSWORDS.hash(password)
                if args.command != "enable-user":
                    session.execute(update(AccessSession).where(AccessSession.user_id == user.id).values(revoked_at=int(time.time())))
            print(f"Completed {args.command} for {username}.")
    except (ValueError, IntegrityError) as error:
        # Database exceptions can include SQL parameters; never print them.
        message = str(error) if isinstance(error, ValueError) else "username already exists or database constraint failed"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        db.close()


if __name__ == "__main__":
    main()
