CREATE EXTENSION IF NOT EXISTS pg_trgm;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_email_normalized_check'
  ) THEN
    ALTER TABLE "users"
      ADD CONSTRAINT "users_email_normalized_check"
      CHECK ("email" = lower(btrim("email")))
      NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'banned_emails_email_normalized_check'
  ) THEN
    ALTER TABLE "banned_emails"
      ADD CONSTRAINT "banned_emails_email_normalized_check"
      CHECK ("email" = lower(btrim("email")))
      NOT VALID;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS "idx_alerts_item_name_trgm"
  ON "alerts" USING gin ("item_name" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "idx_users_username_trgm"
  ON "users" USING gin ("username" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS "idx_users_email_trgm"
  ON "users" USING gin ("email" gin_trgm_ops);
