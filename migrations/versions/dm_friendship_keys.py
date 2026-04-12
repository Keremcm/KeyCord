"""
Migration: Arkadaşlıklar için ortak DM anahtarı field'ları eklendi.
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('friendship', sa.Column('encrypted_dm_key_user', sa.Text(), nullable=True))
    op.add_column('friendship', sa.Column('encrypted_dm_key_friend', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('friendship', 'encrypted_dm_key_user')
    op.drop_column('friendship', 'encrypted_dm_key_friend')

