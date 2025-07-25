"""Add constraints to Investment model

Revision ID: 39911c4dbc56
Revises: 12412a274f70
Create Date: 2025-07-11 11:26:56.277395

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39911c4dbc56'
down_revision = '12412a274f70'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('investments', schema=None) as batch_op:
        batch_op.alter_column('year_month',
               existing_type=sa.VARCHAR(length=7),
               nullable=False)
        batch_op.alter_column('income',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('saving',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('self_investment',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('financial_investment',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('investments', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('financial_investment',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('self_investment',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('saving',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('income',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('year_month',
               existing_type=sa.VARCHAR(length=7),
               nullable=True)

    # ### end Alembic commands ###
