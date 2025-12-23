"""fix_invitation_timestamp_timezone

Revision ID: 3d4636fd8531
Revises: 2aab15788fad
Create Date: 2025-12-25 07:49:53.956523

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3d4636fd8531'
down_revision: Union[str, Sequence[str], None] = '2aab15788fad'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Change invitation timestamp columns from TIMESTAMP WITHOUT TIME ZONE to TIMESTAMP WITH TIME ZONE
    op.execute('ALTER TABLE invitations ALTER COLUMN expires_at TYPE TIMESTAMP WITH TIME ZONE')
    op.execute('ALTER TABLE invitations ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE')


def downgrade() -> None:
    """Downgrade schema."""
    # Revert timestamp columns back to TIMESTAMP WITHOUT TIME ZONE
    op.execute('ALTER TABLE invitations ALTER COLUMN expires_at TYPE TIMESTAMP WITHOUT TIME ZONE')
    op.execute('ALTER TABLE invitations ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE')
