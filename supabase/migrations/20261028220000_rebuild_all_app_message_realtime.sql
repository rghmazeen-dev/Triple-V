-- Rebuild all application-owned message tables and their Postgres Changes membership.
-- This intentionally discards the 3 rows currently in private_messages.
-- message_reactions, chat_pins, and the legacy public.messages table are empty.
-- Supabase-managed realtime.* tables/publications are intentionally untouched.
-- chat_requests, approved_user_directory, and mazen_auto_reply_window are preserved.

-- Detach the app-owned tables from the public Realtime publication before dropping them.
ALTER PUBLICATION supabase_realtime DROP TABLE public.private_messages, public.message_reactions, public.messages;

-- Remove app trigger/function before replacing the message table.
DROP TRIGGER IF EXISTS mazen_temp_auto_reply ON public.private_messages;
DROP FUNCTION IF EXISTS public.mazen_auto_reply_to_private_message();

-- Drop only app-owned message tables; there are no foreign-key dependents.
DROP TABLE public.private_messages;
DROP TABLE public.message_reactions;
DROP TABLE public.chat_pins;
DROP TABLE public.messages;

-- Private chat messages.
CREATE TABLE public.private_messages (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sender text NOT NULL,
  receiver text NOT NULL,
  content text NOT NULL,
  created_at timestamptz DEFAULT now()
);

-- Reactions attached to private message IDs.
CREATE TABLE public.message_reactions (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  message_id bigint NOT NULL,
  username text NOT NULL,
  emoji text NOT NULL,
  created_at timestamptz DEFAULT now()
);

-- User-pinned messages.
CREATE TABLE public.chat_pins (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_a text NOT NULL,
  user_b text NOT NULL,
  message_id text NOT NULL,
  snippet text,
  created_at timestamptz DEFAULT now()
);

-- Legacy public message stream; retained as an empty app-owned table.
CREATE TABLE public.messages (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  user_name text NOT NULL,
  content text NOT NULL
);

ALTER TABLE public.private_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

GRANT ALL ON TABLE public.private_messages TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.message_reactions TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.chat_pins TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.messages TO anon, authenticated, service_role;
GRANT USAGE, SELECT ON SEQUENCE public.private_messages_id_seq TO anon, authenticated, service_role;
GRANT USAGE, SELECT ON SEQUENCE public.message_reactions_id_seq TO anon, authenticated, service_role;
GRANT USAGE, SELECT ON SEQUENCE public.chat_pins_id_seq TO anon, authenticated, service_role;
GRANT USAGE, SELECT ON SEQUENCE public.messages_id_seq TO anon, authenticated, service_role;

-- Retain the current application access behavior for private chat.
CREATE POLICY "anon full access" ON public.private_messages FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "admin full access" ON public.private_messages FOR ALL TO authenticated USING ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text) WITH CHECK ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text);
CREATE POLICY "Users can read own messages" ON public.private_messages FOR SELECT TO authenticated USING ((sender = (auth.jwt() ->> 'username'::text)) OR (receiver = (auth.jwt() ->> 'username'::text)));
CREATE POLICY "Users can send messages" ON public.private_messages FOR INSERT TO authenticated WITH CHECK (sender = (auth.jwt() ->> 'username'::text));

CREATE POLICY "Allow delete for all" ON public.message_reactions FOR DELETE TO public USING (true);
CREATE POLICY "Allow insert for all" ON public.message_reactions FOR INSERT TO public WITH CHECK (true);
CREATE POLICY "Allow read for all" ON public.message_reactions FOR SELECT TO public USING (true);
CREATE POLICY "Allow update for all" ON public.message_reactions FOR UPDATE TO public USING (true) WITH CHECK (true);
CREATE POLICY "Users can add own reactions" ON public.message_reactions FOR INSERT TO authenticated WITH CHECK (username = (auth.jwt() ->> 'username'::text));
CREATE POLICY "Users can delete own reactions" ON public.message_reactions FOR DELETE TO authenticated USING (username = (auth.jwt() ->> 'username'::text));
CREATE POLICY "Users can view reactions" ON public.message_reactions FOR SELECT TO authenticated USING (true);
CREATE POLICY "admin full access" ON public.message_reactions FOR ALL TO authenticated USING ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text) WITH CHECK ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text);
CREATE POLICY "anon full access" ON public.message_reactions FOR ALL TO anon USING (true) WITH CHECK (true);

CREATE POLICY "Users can create pins" ON public.chat_pins FOR INSERT TO authenticated WITH CHECK (user_a = (auth.jwt() ->> 'username'::text));
CREATE POLICY "Users can view own pins" ON public.chat_pins FOR SELECT TO authenticated USING ((user_a = (auth.jwt() ->> 'username'::text)) OR (user_b = (auth.jwt() ->> 'username'::text)));
CREATE POLICY "admin full access" ON public.chat_pins FOR ALL TO authenticated USING ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text) WITH CHECK ((auth.jwt() ->> 'email'::text) = 'mazenramy985@gmail.com'::text);
CREATE POLICY "anon full access" ON public.chat_pins FOR ALL TO anon USING (true) WITH CHECK (true);

-- Preserve the existing legacy-table policy (authenticated users can read).
CREATE POLICY "Allow authenticated read" ON public.messages FOR SELECT TO authenticated USING (true);
CREATE POLICY "Allow authenticated users to read messages" ON public.messages FOR SELECT TO authenticated USING (true);

-- Rebuild the message handler function while preserving the configured time window and reply text.
CREATE FUNCTION public.mazen_auto_reply_to_private_message()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE
  v_window public.mazen_auto_reply_window%ROWTYPE;
  v_now timestamptz;
BEGIN
  IF NEW.sender IS NULL
     OR NEW.receiver IS NULL
     OR lower(btrim(NEW.receiver)) <> 'mazen'
     OR lower(btrim(NEW.sender)) = 'mazen' THEN
    RETURN NEW;
  END IF;

  SELECT w.* INTO v_window
  FROM public.mazen_auto_reply_window AS w
  WHERE w.id IS TRUE
  LIMIT 1;

  IF NOT FOUND OR v_window.enabled IS NOT TRUE THEN
    RETURN NEW;
  END IF;

  v_now := clock_timestamp();
  IF v_now < v_window.starts_at OR v_now >= v_window.expires_at THEN
    RETURN NEW;
  END IF;

  INSERT INTO public.private_messages (sender, receiver, content)
  VALUES ('Mazen', NEW.sender, v_window.reply_text);

  RETURN NEW;
END;
$function$;

CREATE TRIGGER mazen_temp_auto_reply
AFTER INSERT ON public.private_messages
FOR EACH ROW EXECUTE FUNCTION public.mazen_auto_reply_to_private_message();

-- Restore only app-owned message tables to the public Realtime publication.
ALTER PUBLICATION supabase_realtime ADD TABLE public.private_messages, public.message_reactions, public.messages;
