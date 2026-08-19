-- Make users.phone nullable and non-unique.
--
-- WHY THIS FILE EXISTS. The hub creates its schema with Base.metadata.create_all,
-- which adds missing tables but never alters existing columns. A database that
-- already has a users table therefore keeps NOT NULL and the UNIQUE index no
-- matter what the model says, and registrations without a phone -- or sharing
-- one -- keep failing at the database rather than at the model. There is no
-- Alembic in this repository, so the upgrade is explicit.
--
--   psql "$HUB_DATABASE_URL" -f scripts/schema_upgrade_phone_20260819.sql
--
-- WHY THE CHANGE. A UNIQUE NOT NULL phone encodes an assumption that does not
-- hold for this user base. Measured against the AR 1.0 population being
-- migrated, it rejected 85 of 345 real accounts: 8 registered without a phone
-- and 77 sharing a number with another account -- a household or a cooperative
-- using one line. Dropping a quarter of the growers to preserve a schema
-- convenience is the wrong trade.
--
-- email keeps UNIQUE NOT NULL, which costs nothing: that same population has
-- zero missing and zero duplicate emails, so it remains the identity anchor.
--
-- Idempotent, and safe to run BEFORE deploying the code: relaxing a constraint
-- cannot invalidate rows that already satisfy the stricter one, and the old code
-- keeps working because it only ever wrote unique non-null phones.
--
-- IRREVERSIBLE IN PRACTICE. Once duplicate or null phones exist, restoring the
-- constraint requires deciding what to do with them. That is the intended
-- direction, but it is a one-way door and worth knowing before running it.

BEGIN;

ALTER TABLE users
    ALTER COLUMN phone DROP NOT NULL;

-- The UNIQUE index name depends on how it was created: SQLAlchemy's
-- unique=True on an indexed column yields ix_users_phone as a unique index,
-- while a table-level constraint yields users_phone_key. Drop whichever exists
-- and leave the other alone.
DROP INDEX IF EXISTS ix_users_phone;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_phone_key;

-- Keep a non-unique index: lookups by phone are still a supported path, and
-- dropping the index would quietly turn every one of them into a table scan.
CREATE INDEX IF NOT EXISTS ix_users_phone ON users (phone);

COMMIT;

-- Verify:
--   \d users
-- phone should read "character varying(20)" with no "not null", and
-- ix_users_phone should appear as btree without the word UNIQUE.
