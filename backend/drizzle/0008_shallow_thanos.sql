-- This migration is intentionally limited to pending_challenges.
-- Other objects that previously existed here are already created by:
-- - 0005_avatar_support.sql
-- - 0006_user_moderation.sql
-- - 0007_restriction_system.sql

CREATE TABLE IF NOT EXISTS "pending_challenges" (
	"key" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_pending_challenges_expires" ON "pending_challenges" USING btree ("expires_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_pending_challenges_type" ON "pending_challenges" USING btree ("type");
