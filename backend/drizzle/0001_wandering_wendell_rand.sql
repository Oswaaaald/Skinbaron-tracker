ALTER TABLE "alerts" ADD COLUMN "notified_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "idx_alerts_notified" ON "alerts" USING btree ("rule_id","notified_at");