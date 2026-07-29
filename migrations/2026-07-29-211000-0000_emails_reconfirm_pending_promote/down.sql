CREATE OR REPLACE FUNCTION reconfirm_email_on_email_change() RETURNS trigger AS $$
  BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email THEN
      NEW.token := random_string(26);
      NEW.verified := false;
    END IF;
    RETURN NEW;
  END
$$ LANGUAGE plpgsql;
