"""add_invited_by_to_invitations

Revision ID: 7467e415a5fc
Revises: 3d4636fd8531
Create Date: 2025-12-25 07:53:51.724987

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7467e415a5fc'
down_revision: Union[str, Sequence[str], None] = '3d4636fd8531'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add invited_by column to invitations table
    # First add as nullable to handle existing rows
    op.add_column('invitations', sa.Column('invited_by', sa.UUID(), nullable=True))

    # Delete any existing invitations that don't have invited_by (old test data)
    op.execute('DELETE FROM invitations WHERE invited_by IS NULL')

    # Now make it NOT NULL and add foreign key
    op.alter_column('invitations', 'invited_by', nullable=False)
    op.create_foreign_key('fk_invitations_invited_by_users', 'invitations', 'users', ['invited_by'], ['id'])
    op.create_index('ix_invitations_invited_by', 'invitations', ['invited_by'])


def downgrade() -> None:
    """Downgrade schema."""
    # Remove the invited_by column
    op.drop_index('ix_invitations_invited_by', table_name='invitations')
    op.drop_constraint('fk_invitations_invited_by_users', 'invitations', type_='foreignkey')
    op.drop_column('invitations', 'invited_by')
