-- Migration: Replace freeze/ban with unified restriction system + sanctions history

-- Drop old freeze/ban columns
ALTER TABLE "users" DROP COLUMN IF EXISTS "is_frozen";
ALTER TABLE "users" DROP COLUMN IF EXISTS "frozen_at";
ALTER TABLE "users" DROP COLUMN IF EXISTS "frozen_reason";
ALTER TABLE "users" DROP COLUMN IF EXISTS "is_banned";
ALTER TABLE "users" DROP COLUMN IF EXISTS "banned_at";
ALTER TABLE "users" DROP COLUMN IF EXISTS "ban_reason";

-- Add new restriction columns
ALTER TABLE "users" ADD COLUMN "is_restricted" boolean DEFAULT false NOT NULL;
ALTER TABLE "users" ADD COLUMN "restriction_type" text;
ALTER TABLE "users" ADD COLUMN "restriction_reason" text;
ALTER TABLE "users" ADD COLUMN "restriction_expires_at" timestamp with time zone;
ALTER TABLE "users" ADD COLUMN "restricted_at" timestamp with time zone;
ALTER TABLE "users" ADD COLUMN "restricted_by_admin_id" integer REFERENCES "users"("id") ON DELETE SET NULL;

-- Create sanctions table (sanction history / casier)
CREATE TABLE IF NOT EXISTS "sanctions" (
  "id" serial PRIMARY KEY NOT NULL,
  "user_id" integer NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
  "admin_id" integer REFERENCES "users"("id") ON DELETE SET NULL,
  "admin_username" text NOT NULL,
  "action" text NOT NULL,
  "restriction_type" text,
  "reason" text,
  "duration_hours" integer,
  "expires_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_sanctions_user_id" ON "sanctions" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_sanctions_created_at" ON "sanctions" ("created_at");
