-- Reconcile pending_challenges table on environments where historical migration
-- ordering caused 0008_shallow_thanos.sql to be skipped.
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
