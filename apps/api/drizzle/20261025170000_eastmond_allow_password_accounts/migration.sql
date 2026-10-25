-- client/eastmond proof of concept only. The instance cannot deliver email, so
-- firm users sign in with operator-provisioned passwords instead of email
-- codes, which needs more than one credential account.
SET lock_timeout = '1s';--> statement-breakpoint
SET statement_timeout = '5s';--> statement-breakpoint
SET statement_timeout = 0;--> statement-breakpoint
-- squawk-ignore transaction-nesting
COMMIT;
--> statement-breakpoint
-- stella-migration-safety: reviewed drop-object - only drops a partial unique index, no data; the bootstrap sign-up it guarded is closed once the owner exists. Rollback: CREATE UNIQUE INDEX CONCURRENTLY "account_credential_singleton_uidx" ON "account" ("provider_id") WHERE provider_id = 'credential', after removing extra credential accounts.
DROP INDEX CONCURRENTLY IF EXISTS "account_credential_singleton_uidx";
--> statement-breakpoint
-- squawk-ignore transaction-nesting, ban-uncommitted-transaction
BEGIN;
--> statement-breakpoint
SET statement_timeout = '5s';
