-- Reversible conversation visibility controlled only by the Mazen account.
-- Messages are preserved; this table only controls whether the pair appears in chat lists.
CREATE TABLE IF NOT EXISTS public.mazen_hidden_chats (
  chat_key text PRIMARY KEY,
  user_a text NOT NULL,
  user_b text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT mazen_hidden_chats_not_self CHECK (lower(btrim(user_a)) <> lower(btrim(user_b)))
);

ALTER TABLE public.mazen_hidden_chats ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.mazen_chat_key(p_left text, p_right text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE WHEN lower(btrim(p_left)) < lower(btrim(p_right))
    THEN lower(btrim(p_left)) || '::' || lower(btrim(p_right))
    ELSE lower(btrim(p_right)) || '::' || lower(btrim(p_left))
  END;
$$;

CREATE OR REPLACE FUNCTION public.get_hidden_chat_partners(p_username text)
RETURNS TABLE(username text)
LANGUAGE sql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $$
  SELECT CASE
    WHEN lower(btrim(h.user_a)) = lower(btrim(p_username)) THEN h.user_b
    ELSE h.user_a
  END AS username
  FROM public.mazen_hidden_chats h
  WHERE lower(btrim(h.user_a)) = lower(btrim(p_username))
     OR lower(btrim(h.user_b)) = lower(btrim(p_username));
$$;

CREATE OR REPLACE FUNCTION public.hide_private_chat(p_actor text, p_target text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $$
DECLARE
  v_target text := btrim(coalesce(p_target, ''));
BEGIN
  IF lower(btrim(coalesce(p_actor, ''))) <> 'mazen'
     OR v_target = ''
     OR lower(v_target) = 'mazen' THEN
    RETURN false;
  END IF;
  INSERT INTO public.mazen_hidden_chats(chat_key, user_a, user_b)
  VALUES (public.mazen_chat_key('Mazen', v_target), 'Mazen', v_target)
  ON CONFLICT (chat_key) DO NOTHING;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.unhide_private_chat(p_actor text, p_target text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $$
BEGIN
  IF lower(btrim(coalesce(p_actor, ''))) <> 'mazen'
     OR btrim(coalesce(p_target, '')) = ''
     OR lower(btrim(p_target)) = 'mazen' THEN
    RETURN false;
  END IF;
  DELETE FROM public.mazen_hidden_chats
  WHERE chat_key = public.mazen_chat_key('Mazen', btrim(p_target));
  RETURN true;
END;
$$;

REVOKE ALL ON TABLE public.mazen_hidden_chats FROM anon, authenticated;
REVOKE ALL ON FUNCTION public.mazen_chat_key(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_hidden_chat_partners(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.hide_private_chat(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.unhide_private_chat(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mazen_chat_key(text, text) TO service_role;
