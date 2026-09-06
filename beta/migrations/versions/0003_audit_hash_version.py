"""Bind tenant into new evidence hashes; preserve old hash verification."""
from alembic import op
import sqlalchemy as sa
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("audit_records", sa.Column("hash_version", sa.Integer(), nullable=False, server_default="1"))

def downgrade():
    with op.batch_alter_table("audit_records") as batch:
        batch.drop_column("hash_version")
