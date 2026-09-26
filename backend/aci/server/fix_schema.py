"""Startup schema hook — now a no-op.

Schema is owned by Alembic migrations. This used to apply ad-hoc DDL at startup
(add api_key_id columns, create billing tables, seed plans), but it drifted from
the models, referenced a non-existent config helper, and added an api_key_id FK
that is incompatible with the LYZR_API_KEY_ID_DB sentinel. Those fixes now live
in the migration `d1e2f3a4b5c6_alpha_owner_schema_fixes`. Kept as a no-op so the
`main.py` import/call site stays valid.
"""

from aci.common.logging_setup import get_logger

logger = get_logger(__name__)


def fix_schema() -> None:
    """No-op: schema is managed by Alembic migrations."""
    logger.info("fix_schema: schema managed by Alembic migrations; nothing to do")


if __name__ == "__main__":
    fix_schema()
