"""empty message

Revision ID: fd00e28882f4
Revises: 
Create Date: 2022-06-30 11:54:09.055109

"""
import json
import os

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "fd00e28882f4"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    user = op.create_table(
        "Users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("hashed_password", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.bulk_insert(
        user,
        [
            {"id": 1, "username": "Namo", "hashed_password": "123456"},
            {"id": 2, "username": "NNS", "hashed_password": "654321"},
        ],
    )

    op.create_index(op.f("ix_Users_id"), "Users", ["id"], unique=False)
    op.create_index(
        op.f("ix_Users_username"), "Users", ["username"], unique=True
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_Users_username"), table_name="Users")
    op.drop_index(op.f("ix_Users_id"), table_name="Users")
    op.drop_table("Users")
    # ### end Alembic commands ###