-- Rebuild the private chat message tables after explicit user approval.
-- This intentionally removes the current rows from private_messages (67),
-- message_reactions (1), and chat_pins (0). It does not touch public.messages,
-- Supabase-managed realtime.* objects, or Storage files.

ALTER PUBLICATION supabase_realtime DROP TABLE public.private_messages, public.message_reactions;

DROP TABLE public.private_messages;
DROP TABLE public.message_reactions;
DROP TABLE public.chat_pins;

CREATE TABLE public.private_messages (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sender text NOT NULL,
  receiver text NOT NULL,
  content text NOT NULL,
  created_at timestamptz DEFAULT now()
);

CREATE SEQUENCE public.message_reactions_id_seq AS integer;
CREATE TABLE public.message_reactions (
  id integer NOT NULL DEFAULT nextval('public.message_reactions_id_seq'::regclass) PRIMARY KEY,
  message_id bigint NOT NULL,
  username text NOT NULL,
  emoji text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER SEQUENCE public.message_reactions_id_seq OWNED BY public.message_reactions.id;

CREATE SEQUENCE public.chat_pins_id_seq AS bigint;
CREATE TABLE public.chat_pins (
  id bigint NOT NULL DEFAULT nextval('public.chat_pins_id_seq'::regclass) PRIMARY KEY,
  user_a text NOT NULL,
  user_b text NOT NULL,
  message_id text NOT NULL,
  snippet text,
  created_at timestamptz DEFAULT now()
);
ALTER SEQUENCE public.chat_pins_id_seq OWNED BY public.chat_pins.id;

ALTER TABLE public.private_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.message_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_pins ENABLE ROW LEVEL SECURITY;

GRANT ALL ON TABLE public.private_messages TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.message_reactions TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.chat_pins TO anon, authenticated, service_role;
GRANT USAGE ON SEQUENCE public.message_reactions_id_seq TO anon, authenticated, service_role;
GRANT USAGE ON SEQUENCE public.chat_pins_id_seq TO anon, authenticated, service_role;

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

ALTER PUBLICATION supabase_realtime ADD TABLE public.private_messages, public.message_reactions;

CREATE TRIGGER mazen_temp_auto_reply
AFTER INSERT ON public.private_messages
FOR EACH ROW EXECUTE FUNCTION public.mazen_auto_reply_to_private_message();
