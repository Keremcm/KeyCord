"""add dm key columns to friendship

Revision ID: xxxxxx_dmkey
Revises: 58467bb10a26
Create Date: 2026-01-24

"""
from alembic import op
import sqlalchemy as sa

revision = 'xxxxxx_dmkey'
down_revision = '58467bb10a26'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('friendship', sa.Column('encrypted_dm_key_user', sa.Text(), nullable=True))
    op.add_column('friendship', sa.Column('encrypted_dm_key_friend', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('friendship', 'encrypted_dm_key_user')
    op.drop_column('friendship', 'encrypted_dm_key_friend')

