-- Auto-update updated_at on row modification (defense-in-depth for manual SET in repos)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON "users"
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_rules_updated_at
  BEFORE UPDATE ON "rules"
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_user_webhooks_updated_at
  BEFORE UPDATE ON "user_webhooks"
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
