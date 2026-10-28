-- Keep a minimal public directory of approved usernames only.
-- Do not expose account_requests fields such as passwords through the directory.
CREATE TABLE public.approved_user_directory (
  username text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.approved_user_directory ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON TABLE public.approved_user_directory TO anon, authenticated, service_role;
CREATE POLICY "Approved usernames are discoverable" ON public.approved_user_directory
  FOR SELECT TO anon, authenticated USING (true);

CREATE OR REPLACE FUNCTION public.sync_approved_user_directory()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM public.approved_user_directory WHERE username = OLD.username;
    RETURN OLD;
  END IF;

  IF TG_OP = 'UPDATE' AND OLD.username IS DISTINCT FROM NEW.username THEN
    DELETE FROM public.approved_user_directory WHERE username = OLD.username;
  END IF;

  IF NEW.status = 'approved' AND NULLIF(BTRIM(NEW.username), '') IS NOT NULL THEN
    INSERT INTO public.approved_user_directory (username)
    VALUES (BTRIM(NEW.username))
    ON CONFLICT (username) DO NOTHING;
  ELSE
    DELETE FROM public.approved_user_directory WHERE username = NEW.username;
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER account_requests_directory_insert
AFTER INSERT ON public.account_requests
FOR EACH ROW EXECUTE FUNCTION public.sync_approved_user_directory();

CREATE TRIGGER account_requests_directory_update
AFTER UPDATE OF status, username ON public.account_requests
FOR EACH ROW EXECUTE FUNCTION public.sync_approved_user_directory();

CREATE TRIGGER account_requests_directory_delete
AFTER DELETE ON public.account_requests
FOR EACH ROW EXECUTE FUNCTION public.sync_approved_user_directory();

INSERT INTO public.approved_user_directory (username)
SELECT BTRIM(username)
FROM public.account_requests
WHERE status = 'approved' AND NULLIF(BTRIM(username), '') IS NOT NULL
ON CONFLICT (username) DO NOTHING;

ALTER PUBLICATION supabase_realtime ADD TABLE public.approved_user_directory;
