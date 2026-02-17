-- User moderation: freeze, ban, and banned emails
ALTER TABLE "users" ADD COLUMN "is_frozen" boolean DEFAULT false NOT NULL;
ALTER TABLE "users" ADD COLUMN "frozen_at" timestamp with time zone;
ALTER TABLE "users" ADD COLUMN "frozen_reason" text;
ALTER TABLE "users" ADD COLUMN "is_banned" boolean DEFAULT false NOT NULL;
ALTER TABLE "users" ADD COLUMN "banned_at" timestamp with time zone;
ALTER TABLE "users" ADD COLUMN "ban_reason" text;

CREATE TABLE "banned_emails" (
  "id" serial PRIMARY KEY NOT NULL,
  "email" text NOT NULL UNIQUE,
  "reason" text,
  "banned_by_admin_id" integer REFERENCES "users"("id") ON DELETE SET NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX "idx_banned_emails_email" ON "banned_emails" USING btree ("email");
