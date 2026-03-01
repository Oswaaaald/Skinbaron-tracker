-- CHECK constraints for rules table
ALTER TABLE "rules" ADD CONSTRAINT "rules_min_price_non_negative" CHECK ("min_price" >= 0);
ALTER TABLE "rules" ADD CONSTRAINT "rules_max_price_non_negative" CHECK ("max_price" >= 0);
ALTER TABLE "rules" ADD CONSTRAINT "rules_price_range_valid" CHECK ("min_price" IS NULL OR "max_price" IS NULL OR "min_price" <= "max_price");
ALTER TABLE "rules" ADD CONSTRAINT "rules_min_wear_range" CHECK ("min_wear" IS NULL OR ("min_wear" >= 0 AND "min_wear" <= 1));
ALTER TABLE "rules" ADD CONSTRAINT "rules_max_wear_range" CHECK ("max_wear" IS NULL OR ("max_wear" >= 0 AND "max_wear" <= 1));
ALTER TABLE "rules" ADD CONSTRAINT "rules_wear_range_valid" CHECK ("min_wear" IS NULL OR "max_wear" IS NULL OR "min_wear" <= "max_wear");

-- CHECK constraints for alerts table
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_price_non_negative" CHECK ("price" >= 0);
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_wear_value_range" CHECK ("wear_value" IS NULL OR ("wear_value" >= 0 AND "wear_value" <= 1));
