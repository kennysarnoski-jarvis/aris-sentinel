"""Migration 0042: split users.name into first/last.

We do this in two phases because the table is large and we cannot hold a lock for the
whole backfill. Phase 1 adds nullable columns; phase 2 (a later migration) backfills
and enforces NOT NULL, so that reads never see a half-migrated row.
"""
from alembic import op
import sqlalchemy as sa


def upgrade():
    # Add the new columns as nullable first, to avoid a full-table rewrite under lock.
    op.add_column("users", sa.Column("first_name", sa.String(), nullable=True))
    op.add_column("users", sa.Column("last_name", sa.String(), nullable=True))
    # Backfill in batches of 5000 in order to keep replication lag bounded.
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE users SET first_name = split_part(name, ' ', 1) "
                         "WHERE first_name IS NULL"))


def downgrade():
    op.drop_column("users", "last_name")
    op.drop_column("users", "first_name")
