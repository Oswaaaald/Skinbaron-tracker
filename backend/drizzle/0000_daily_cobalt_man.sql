CREATE TYPE "public"."filter_enum" AS ENUM('all', 'only', 'exclude');--> statement-breakpoint
CREATE TYPE "public"."notification_style_enum" AS ENUM('compact', 'detailed');--> statement-breakpoint
CREATE TYPE "public"."webhook_type_enum" AS ENUM('discord');--> statement-breakpoint
CREATE TABLE "access_token_blacklist" (
	"jti" text PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "admin_actions" (
	"id" serial PRIMARY KEY NOT NULL,
	"admin_user_id" integer NOT NULL,
	"action" text NOT NULL,
	"target_user_id" integer,
	"details" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" serial PRIMARY KEY NOT NULL,
	"rule_id" integer NOT NULL,
	"sale_id" text NOT NULL,
	"item_name" text NOT NULL,
	"price" real NOT NULL,
	"wear_value" real,
	"stattrak" boolean DEFAULT false NOT NULL,
	"souvenir" boolean DEFAULT false NOT NULL,
	"has_stickers" boolean DEFAULT false NOT NULL,
	"skin_url" text NOT NULL,
	"sent_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alerts_rule_sale_unique" UNIQUE("rule_id","sale_id")
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"event_type" text NOT NULL,
	"event_data" text,
	"ip_address" text,
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"token_hash" text NOT NULL,
	"token_jti" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"replaced_by_jti" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "refresh_tokens_token_hash_unique" UNIQUE("token_hash"),
	CONSTRAINT "refresh_tokens_token_jti_unique" UNIQUE("token_jti")
);
--> statement-breakpoint
CREATE TABLE "rule_webhooks" (
	"rule_id" integer NOT NULL,
	"webhook_id" integer NOT NULL,
	CONSTRAINT "rule_webhooks_rule_id_webhook_id_pk" PRIMARY KEY("rule_id","webhook_id")
);
--> statement-breakpoint
CREATE TABLE "rules" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"search_item" text NOT NULL,
	"min_price" real,
	"max_price" real,
	"min_wear" real,
	"max_wear" real,
	"stattrak_filter" "filter_enum" DEFAULT 'all' NOT NULL,
	"souvenir_filter" "filter_enum" DEFAULT 'all' NOT NULL,
	"sticker_filter" "filter_enum" DEFAULT 'all' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_webhooks" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"name" text NOT NULL,
	"webhook_url_encrypted" text NOT NULL,
	"webhook_type" "webhook_type_enum" DEFAULT 'discord' NOT NULL,
	"notification_style" "notification_style_enum" DEFAULT 'compact' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhooks_user_name_unique" UNIQUE("user_id","name")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"username" text NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"is_admin" boolean DEFAULT false NOT NULL,
	"is_super_admin" boolean DEFAULT false NOT NULL,
	"is_approved" boolean DEFAULT false NOT NULL,
	"totp_enabled" boolean DEFAULT false NOT NULL,
	"totp_secret_encrypted" text,
	"recovery_codes_encrypted" text,
	"tos_accepted_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "access_token_blacklist" ADD CONSTRAINT "access_token_blacklist_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_actions" ADD CONSTRAINT "admin_actions_admin_user_id_users_id_fk" FOREIGN KEY ("admin_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_actions" ADD CONSTRAINT "admin_actions_target_user_id_users_id_fk" FOREIGN KEY ("target_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_rule_id_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_webhooks" ADD CONSTRAINT "rule_webhooks_rule_id_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_webhooks" ADD CONSTRAINT "rule_webhooks_webhook_id_user_webhooks_id_fk" FOREIGN KEY ("webhook_id") REFERENCES "public"."user_webhooks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rules" ADD CONSTRAINT "rules_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_webhooks" ADD CONSTRAINT "user_webhooks_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_token_blacklist_expiry" ON "access_token_blacklist" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_token_blacklist_user" ON "access_token_blacklist" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_admin_actions_admin" ON "admin_actions" USING btree ("admin_user_id");--> statement-breakpoint
CREATE INDEX "idx_admin_actions_target" ON "admin_actions" USING btree ("target_user_id");--> statement-breakpoint
CREATE INDEX "idx_admin_actions_created" ON "admin_actions" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_admin_actions_admin_created" ON "admin_actions" USING btree ("admin_user_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_sale_id" ON "alerts" USING btree ("sale_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_rule_id" ON "alerts" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "idx_alerts_sent_at" ON "alerts" USING btree ("sent_at");--> statement-breakpoint
CREATE INDEX "idx_alerts_rule_sent" ON "alerts" USING btree ("rule_id","sent_at");--> statement-breakpoint
CREATE INDEX "idx_audit_log_event_type" ON "audit_log" USING btree ("event_type");--> statement-breakpoint
CREATE INDEX "idx_audit_log_created_at" ON "audit_log" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_log_user_created" ON "audit_log" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_user_event_date" ON "audit_log" USING btree ("user_id","event_type","created_at");--> statement-breakpoint
CREATE INDEX "idx_audit_event_created" ON "audit_log" USING btree ("event_type","created_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_expiry" ON "refresh_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_revoked" ON "refresh_tokens" USING btree ("revoked_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_user_expires" ON "refresh_tokens" USING btree ("user_id","expires_at");--> statement-breakpoint
CREATE INDEX "idx_refresh_tokens_expiry_revoked" ON "refresh_tokens" USING btree ("expires_at","revoked_at");--> statement-breakpoint
CREATE INDEX "idx_rule_webhooks_webhook" ON "rule_webhooks" USING btree ("webhook_id");--> statement-breakpoint
CREATE INDEX "idx_rules_enabled" ON "rules" USING btree ("enabled");--> statement-breakpoint
CREATE INDEX "idx_rules_user_enabled" ON "rules" USING btree ("user_id","enabled");--> statement-breakpoint
CREATE INDEX "idx_webhooks_user_active" ON "user_webhooks" USING btree ("user_id","is_active");--> statement-breakpoint
CREATE INDEX "idx_users_approved" ON "users" USING btree ("is_approved");--> statement-breakpoint
CREATE INDEX "idx_users_admin_approved" ON "users" USING btree ("is_admin","is_approved");