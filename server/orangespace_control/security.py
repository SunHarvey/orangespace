"""Authentication primitives and exact public DTO conversion."""
import hashlib
import re
import secrets
import time
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from sqlalchemy import select, func
from .schema_v1 import users, sessions, nodes, mappings, grants, audit, locks, rates

PASSWORDS = PasswordHasher()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z', re.ASCII)
USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\Z', re.ASCII)
MAX_INT = 9007199254740991


class ControlError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def now():
    return int(time.time())


def uid():
    return uuid.uuid4().bytes


def canonical(value):
    if not isinstance(value, str):
        raise ValueError('invalid UUID')
    parsed = uuid.UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError('invalid UUID')
    return parsed.bytes


def show(value):
    return str(uuid.UUID(bytes=value))


def username(value):
    if not isinstance(value, str) or not USERNAME.fullmatch(value):
        raise ValueError('invalid username')
    return value.lower()


def token_digest(token):
    return hashlib.sha256(b'OrangeSpace-control-user-v1\x00' + token.encode('ascii')).digest()


def verify(password, encoded):
    try:
        return PASSWORDS.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def user_dto(row):
    return {'central_user_id': show(row['id']), 'username': row['username'], 'role': row['role'],
            'enabled': bool(row['enabled']), 'user_epoch': row['user_epoch'], 'created_at': row['created_at']}


def authority_lock(conn):
    conn.execute(select(locks).where(locks.c.name == 'bootstrap').with_for_update()).one()


def record_audit(conn, actor, action, object_id, before, after, reason, request_id):
    conn.execute(audit.insert().values(id=uid(), actor_id=actor, action=action, object_id=object_id,
                 before_revision=before, after_revision=after, created_at=now(), reason=reason, request_id=request_id))


def authenticate(conn, authorization):
    if not authorization or not authorization.startswith('Bearer ') or not TOKEN.fullmatch(authorization[7:]):
        raise ControlError(401, 'unauthenticated')
    session = conn.execute(select(sessions).where(sessions.c.token_digest == token_digest(authorization[7:])).with_for_update()).mappings().first()
    if not session:
        raise ControlError(401, 'unauthenticated')
    user = conn.execute(select(users).where(users.c.id == session['user_id']).with_for_update()).mappings().one()
    if not user['enabled'] or session['revoked_at'] is not None or session['expires_at'] <= now() or session['user_epoch'] != user['user_epoch']:
        raise ControlError(401, 'unauthenticated')
    return user, session


def throttle(engine, account, source):
    timestamp = now()
    denied = False
    with engine.begin() as conn:
        conn.execute(select(locks).where(locks.c.name == 'login').with_for_update()).one()
        conn.execute(rates.delete().where(rates.c.window_start <= timestamp - 300))
        for label, value, window, maximum in [('account', account, 300, 10), ('source', source, 60, 40)]:
            key = hashlib.sha256((label + ':' + value).encode()).digest()
            row = conn.execute(select(rates).where(rates.c.id == key)).mappings().first()
            if row is None:
                if conn.scalar(select(func.count()).select_from(rates)) >= 4096:
                    denied = True
                    continue
                conn.execute(rates.insert().values(id=key, window_start=timestamp, attempts=1))
            elif row['window_start'] + window <= timestamp:
                conn.execute(rates.update().where(rates.c.id == key).values(window_start=timestamp, attempts=1))
            else:
                denied |= row['attempts'] >= maximum
                conn.execute(rates.update().where(rates.c.id == key).values(attempts=min(maximum + 1, row['attempts'] + 1)))
    if denied:
        raise ControlError(429, 'rate_limited')


def eligible_nodes(conn, user_id, limit=50, cursor=None):
    query = select(nodes, grants.c.id.label('grant_id'), grants.c.grant_epoch, grants.c.scopes,
                   mappings.c.id.label('mapping_id'), mappings.c.mapping_epoch, mappings.c.legacy_user_id).select_from(
                       nodes.join(grants, grants.c.node_id == nodes.c.id).join(mappings, mappings.c.node_id == nodes.c.id)).where(
        grants.c.user_id == user_id, mappings.c.central_user_id == user_id, nodes.c.state == 'active',
        nodes.c.public_key.is_not(None), mappings.c.state == 'approved', grants.c.enabled.is_(True),
        (grants.c.valid_until.is_(None) | (grants.c.valid_until > now())))
    if cursor is not None:
        query = query.where(nodes.c.id > cursor)
    rows = conn.execute(query.order_by(nodes.c.id).limit(limit + 1)).mappings().all()
    items = []
    for row in rows[:limit]:
        items.append({'node_id': show(row['id']), 'alias': row['alias'], 'display_name': row['display_name'],
                      'api_origin': row['api_origin'], 'tls_server_name': row['tls_server_name'],
                      'node_epoch': row['node_epoch'], 'config_revision': row['config_revision'],
                      'key_fingerprint': row['key_fingerprint'].hex(), 'grant_id': show(row['grant_id']),
                      'grant_epoch': row['grant_epoch'], 'scopes': row['scopes'], 'mapping_id': show(row['mapping_id']),
                      'mapping_epoch': row['mapping_epoch'], 'legacy_user_id': show(row['legacy_user_id'])})
    return items, show(rows[limit - 1]['id']) if len(rows) > limit else None
