"""Initial control schema, independent from legacy node tables.

MySQL DDL implicitly commits: failed DDL requires explicit operator recovery,
not a claim of transactional rollback. Downgrade is deliberately forbidden to
preserve permanent identities and revocation history.
"""
from alembic import op
from orangespace_control.schema_v1 import metadata, locks

revision = 'control_0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    for table in metadata.sorted_tables:
        table.create(bind, checkfirst=False)
    bind.execute(locks.insert(), [{'name': 'bootstrap'}, {'name': 'login'}])


def downgrade():
    raise RuntimeError('destructive control-plane downgrade is forbidden')
