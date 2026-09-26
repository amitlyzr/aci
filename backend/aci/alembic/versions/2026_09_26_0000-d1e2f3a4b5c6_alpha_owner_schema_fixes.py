"""Alpha deploy schema fixes: align org_id to VARCHAR, add api_key_id ownership
columns without a FK, and seed the fallback 'team' plan.

These reconcile studio-fork drift that the broken startup fix_schema.py was
meant to handle:
  * projects.org_id / subscriptions.org_id were created as UUID by earlier
    migrations, but the models declare String — queries bind ::VARCHAR and fail
    ("operator does not exist: uuid = character varying").
  * apps/functions need a nullable api_key_id column (custom-app ownership), but
    NOT a FK: seeding sets it to the LYZR_API_KEY_ID_DB sentinel, which is not a
    real api_keys row, so a FK is incompatible.
  * the quota check falls back to a plan named 'team'; an empty plans table gives
    "Subscription plan not found".

Idempotent, so it is safe on a fresh DB and on one already hand-patched.

Revision ID: d1e2f3a4b5c6
Revises: 48bf142a794c
Create Date: 2026-09-26 00:00:00.000000+00:00

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, None] = '48bf142a794c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # org_id -> VARCHAR to match the models (String). USING ::text handles a
    # column that is still uuid; a no-op when it is already varchar.
    op.execute("ALTER TABLE projects ALTER COLUMN org_id TYPE VARCHAR USING org_id::text")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN org_id TYPE VARCHAR USING org_id::text")

    # api_key_id ownership columns, nullable, NO foreign key (see module docstring).
    # Drop any FK a previous fix_schema run added, then ensure the columns exist.
    op.execute("ALTER TABLE apps DROP CONSTRAINT IF EXISTS fk_apps_api_key_id")
    op.execute("ALTER TABLE functions DROP CONSTRAINT IF EXISTS fk_functions_api_key_id")
    op.execute("ALTER TABLE apps ADD COLUMN IF NOT EXISTS api_key_id UUID")
    op.execute("ALTER TABLE functions ADD COLUMN IF NOT EXISTS api_key_id UUID")

    # Seed the fallback 'team' plan (billing.get_active_plan_by_org_id). Features
    # match the CLI seeder's canonical 'team' definition; only projects is read
    # by the project-creation quota check.
    # The features JSON is a bind parameter, not inline SQL — its colons would
    # otherwise be parsed as bind markers by SQLAlchemy's text processing.
    op.execute(
        sa.text(
            """
            INSERT INTO plans (id, name, stripe_product_id, stripe_monthly_price_id,
                               stripe_yearly_price_id, features, is_public, created_at, updated_at)
            VALUES (gen_random_uuid(), 'team', 'prod_team_placeholder',
                    'price_team_monthly_placeholder', 'price_team_yearly_placeholder',
                    CAST(:features AS jsonb), true, now(), now())
            ON CONFLICT (name) DO NOTHING
            """
        ).bindparams(
            features='{"linked_accounts":1000,"api_calls_monthly":300000,'
            '"agent_credentials":10000,"developer_seats":10,"custom_oauth":true,'
            '"log_retention_days":30,"projects":10}'
        )
    )


def downgrade() -> None:
    # org_id is left as VARCHAR (the model-correct type); reverting to uuid is
    # unsafe once non-uuid owner ids exist. Undo the additive parts only.
    op.execute("DELETE FROM plans WHERE name = 'team'")
    op.execute("ALTER TABLE apps DROP COLUMN IF EXISTS api_key_id")
    op.execute("ALTER TABLE functions DROP COLUMN IF EXISTS api_key_id")
