# Database migrations

New database: from beta, set EDA_DATABASE_URL and run `python -m alembic upgrade head`.
0001 is the frozen prototype schema. 0002 adds connector tables without changing prototype data.

Existing prototype databases: back up first, verify the actual schema matches 0001, then explicitly `python -m alembic stamp 0001` and `python -m alembic upgrade head`. Never stamp an unknown schema or automatically infer that all historical deployments match the baseline. Test the process on a restored copy first. Table creation alone cannot verify an existing schema.

The test suite verifies new installation, preserved baseline data, connector-table downgrade and absence of drift on SQLite. A fresh PostgreSQL sandbox migration completed successfully in the live run. Populated PostgreSQL upgrade/downgrade and restore qualification remain pending. Downgrading 0002 discards connector inventory, checkpoints and receipts; use backup restoration if those must survive. Stop collectors before schema changes. Production startup remains gated.
