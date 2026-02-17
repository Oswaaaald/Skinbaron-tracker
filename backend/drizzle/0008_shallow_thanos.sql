CREATE TABLE "banned_emails" (
	"id" serial PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"reason" text,
	"banned_by_admin_id" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "banned_emails_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "pending_challenges" (
	"key" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sanctions" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"admin_id" integer,
	"admin_username" text NOT NULL,
	"action" text NOT NULL,
	"restriction_type" text,
	"reason" text,
	"duration_hours" integer,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "is_restricted" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "restriction_type" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "restriction_reason" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "restriction_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "restricted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "restricted_by_admin_id" integer;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "avatar_filename" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "use_gravatar" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "banned_emails" ADD CONSTRAINT "banned_emails_banned_by_admin_id_users_id_fk" FOREIGN KEY ("banned_by_admin_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sanctions" ADD CONSTRAINT "sanctions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sanctions" ADD CONSTRAINT "sanctions_admin_id_users_id_fk" FOREIGN KEY ("admin_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_banned_emails_email" ON "banned_emails" USING btree ("email");--> statement-breakpoint
CREATE INDEX "idx_pending_challenges_expires" ON "pending_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_pending_challenges_type" ON "pending_challenges" USING btree ("type");--> statement-breakpoint
CREATE INDEX "idx_sanctions_user_id" ON "sanctions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_sanctions_created_at" ON "sanctions" USING btree ("created_at");