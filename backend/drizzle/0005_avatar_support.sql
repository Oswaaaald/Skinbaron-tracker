ALTER TABLE "users" ADD COLUMN "avatar_filename" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "use_gravatar" boolean DEFAULT true NOT NULL;
