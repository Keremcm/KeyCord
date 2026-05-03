"""Add invite code model and invited_by relation

Revision ID: c8bf8d9fe71b
Revises: 58467bb10a26
Create Date: 2026-05-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8bf8d9fe71b'
down_revision = '58467bb10a26'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('invited_by_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_user_invited_by_id_user', 'user', 'user', ['invited_by_id'], ['id'])

    op.create_table(
        'invite_code',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('code', sa.String(length=64), nullable=False),
        sa.Column('inviter_id', sa.Integer(), nullable=False),
        sa.Column('used_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_used', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['inviter_id'], ['user.id'], ),
        sa.ForeignKeyConstraint(['used_by_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code')
    )


def downgrade():
    op.drop_table('invite_code')
    op.drop_constraint('fk_user_invited_by_id_user', 'user', type_='foreignkey')
    op.drop_column('user', 'invited_by_id')
