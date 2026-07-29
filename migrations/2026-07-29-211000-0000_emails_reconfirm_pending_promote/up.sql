-- When promoting emails.pending_email to emails.email after confirm-link,
-- keep verified=true. The legacy reconfirm trigger otherwise forced
-- verified=false on any email column change.
CREATE OR REPLACE FUNCTION reconfirm_email_on_email_change() RETURNS trigger AS $$
  BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email THEN
      IF OLD.pending_email IS NOT NULL
         AND NEW.email IS NOT DISTINCT FROM OLD.pending_email THEN
        NEW.verified := true;
      ELSE
        NEW.token := random_string(26);
        NEW.verified := false;
      END IF;
    END IF;
    RETURN NEW;
  END
$$ LANGUAGE plpgsql;
