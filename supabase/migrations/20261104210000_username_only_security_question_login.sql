-- Username-only chat login: the existing security-question challenge issues a
-- short-lived bearer proof used by session/device/usage RPCs. The legacy
-- password-based RPC overloads remain available for the paused Android app.

-- The web UI uses the SECURITY DEFINER RPCs below; anon does not need direct
-- access to password-bearing account rows or unrestricted session updates.
DROP POLICY IF EXISTS "anon can read accounts" ON public.account_requests;
DROP POLICY IF EXISTS "anon can update own session fields" ON public.account_requests;

CREATE SCHEMA IF NOT EXISTS triple_v_internal;

CREATE TABLE IF NOT EXISTS triple_v_internal.passwordless_login_sessions (
  token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id bigint NOT NULL REFERENCES public.account_requests(id) ON DELETE CASCADE,
  username text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 minutes'),
  revoked_at timestamptz
);

ALTER TABLE triple_v_internal.passwordless_login_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON SCHEMA triple_v_internal FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE triple_v_internal.passwordless_login_sessions FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION triple_v_internal.refresh_passwordless_login_session(p_account_id bigint, p_token text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'triple_v_internal', 'public', 'pg_temp'
AS $function$
BEGIN
  IF nullif(trim(coalesce(p_token, '')), '') IS NULL THEN
    RETURN false;
  END IF;

  UPDATE triple_v_internal.passwordless_login_sessions s
     SET expires_at = clock_timestamp() + interval '30 minutes'
    FROM public.account_requests a
   WHERE s.token::text = p_token
     AND s.account_id = p_account_id
     AND s.revoked_at IS NULL
     AND s.expires_at > clock_timestamp()
     AND a.id = s.account_id
     AND a.status = 'approved';

  RETURN FOUND;
END;
$function$;

REVOKE ALL ON FUNCTION triple_v_internal.refresh_passwordless_login_session(bigint, text) FROM PUBLIC, anon, authenticated;

-- A separate overload preserves the legacy password-based challenge RPC for
-- the paused Android client while the web app starts challenges by username.
CREATE OR REPLACE FUNCTION public.begin_security_challenge(p_username text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_enabled boolean;
  v_count integer;
  v_used integer[];
  v_banned timestamptz;
  v_ids integer[];
  v_token uuid;
  v_questions jsonb;
  v_canonical_username text;
  v_status text;
  v_active_count integer;
BEGIN
  SELECT ar.username, ar.status
    INTO v_canonical_username, v_status
    FROM public.account_requests ar
   WHERE lower(ar.username) = lower(trim(coalesce(p_username, '')))
   LIMIT 1;

  IF v_canonical_username IS NULL THEN
    RETURN jsonb_build_object('found', false);
  END IF;

  IF v_status IS DISTINCT FROM 'approved' THEN
    RETURN jsonb_build_object('found', true, 'status', v_status);
  END IF;

  SELECT questions_enabled, question_count
    INTO v_enabled, v_count
    FROM public.app_security_settings
   WHERE id = true;
  SELECT count(*)::integer INTO v_active_count
    FROM public.security_questions
   WHERE active;

  IF coalesce(v_enabled, false) IS NOT TRUE
     OR coalesce(v_count, 0) <> 36
     OR coalesce(v_active_count, 0) < 6 THEN
    RETURN jsonb_build_object('found', true, 'status', 'approved', 'error', 'security_questions_unavailable');
  END IF;

  INSERT INTO public.security_question_progress(username)
  VALUES (v_canonical_username)
  ON CONFLICT (username) DO NOTHING;

  SELECT used_question_ids, banned_until
    INTO v_used, v_banned
    FROM public.security_question_progress
   WHERE username = v_canonical_username
   FOR UPDATE;

  IF v_banned IS NOT NULL AND v_banned > now() THEN
    RETURN jsonb_build_object('found', true, 'status', 'approved', 'banned_until', v_banned);
  END IF;

  IF coalesce(cardinality(v_used), 0) >= 36 THEN
    v_used := '{}';
    UPDATE public.security_question_progress
       SET used_question_ids = '{}', banned_until = null, updated_at = now()
     WHERE username = v_canonical_username;
  END IF;

  SELECT array_agg(id ORDER BY random()) INTO v_ids
    FROM (
      SELECT q.id
        FROM public.security_questions q
       WHERE q.active AND NOT (q.id = ANY(coalesce(v_used, '{}')))
       ORDER BY random()
       LIMIT 6
    ) pick;

  IF coalesce(cardinality(v_ids), 0) < 6 THEN
    v_used := '{}';
    UPDATE public.security_question_progress
       SET used_question_ids = '{}', banned_until = null, updated_at = now()
     WHERE username = v_canonical_username;
    SELECT array_agg(id ORDER BY random()) INTO v_ids
      FROM (
        SELECT q.id FROM public.security_questions q
         WHERE q.active ORDER BY random() LIMIT 6
      ) pick;
  END IF;

  IF coalesce(cardinality(v_ids), 0) <> 6 THEN
    RETURN jsonb_build_object('found', true, 'status', 'approved', 'error', 'question_bank_incomplete');
  END IF;

  UPDATE public.security_question_progress
     SET used_question_ids = (
           SELECT array_agg(DISTINCT x)
             FROM unnest(coalesce(v_used, '{}') || v_ids) x
         ),
         banned_until = null,
         updated_at = now()
   WHERE username = v_canonical_username;

  INSERT INTO public.security_question_challenges(username, question_ids)
  VALUES (v_canonical_username, v_ids)
  RETURNING token INTO v_token;

  SELECT jsonb_agg(
           jsonb_build_object('id', q.id, 'prompt', q.prompt, 'options', q.options)
           ORDER BY array_position(v_ids, q.id)
         ) INTO v_questions
    FROM public.security_questions q
   WHERE q.id = ANY(v_ids);

  RETURN jsonb_build_object(
    'found', true,
    'status', 'approved',
    'required', true,
    'token', v_token,
    'questions', v_questions
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.verify_security_challenge(p_token uuid, p_answers jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_username text;
  v_ids integer[];
  v_correct integer;
  v_answer_count integer;
  v_distinct_count integer;
  v_banned timestamptz;
  v_account_id bigint;
  v_account_username text;
  v_account_status text;
  v_usage_seconds bigint;
  v_session_token uuid;
BEGIN
  SELECT username, question_ids
    INTO v_username, v_ids
    FROM public.security_question_challenges
   WHERE token = p_token AND consumed = false AND expires_at > now()
   FOR UPDATE;

  IF v_username IS NULL THEN
    RETURN jsonb_build_object('passed', false, 'invalid', true);
  END IF;

  IF p_answers IS NULL
     OR jsonb_typeof(p_answers) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_answers) <> 6 THEN
    UPDATE public.security_question_challenges SET consumed = true WHERE token = p_token;
    RETURN jsonb_build_object('passed', false, 'invalid', true);
  END IF;

  WITH parsed AS (
    SELECT
      CASE WHEN (a->>'id') ~ '^[0-9]+$' THEN (a->>'id')::integer ELSE null END AS qid,
      CASE WHEN (a->>'selected_index') ~ '^[0-9]+$' THEN (a->>'selected_index')::integer ELSE null END AS selected_index
    FROM jsonb_array_elements(p_answers) a
  )
  SELECT count(*), count(DISTINCT qid)
    INTO v_answer_count, v_distinct_count
    FROM parsed
   WHERE qid = ANY(v_ids) AND selected_index IS NOT NULL;

  IF v_answer_count <> 6 OR v_distinct_count <> 6 THEN
    UPDATE public.security_question_challenges SET consumed = true WHERE token = p_token;
    RETURN jsonb_build_object('passed', false, 'invalid', true);
  END IF;

  WITH parsed AS (
    SELECT
      CASE WHEN (a->>'id') ~ '^[0-9]+$' THEN (a->>'id')::integer ELSE null END AS qid,
      CASE WHEN (a->>'selected_index') ~ '^[0-9]+$' THEN (a->>'selected_index')::integer ELSE null END AS selected_index
    FROM jsonb_array_elements(p_answers) a
  )
  SELECT count(*)
    INTO v_correct
    FROM parsed a
    JOIN public.security_questions q ON q.id = a.qid AND q.active
   WHERE q.correct_index = a.selected_index;

  UPDATE public.security_question_challenges SET consumed = true WHERE token = p_token;

  IF v_correct >= 4 THEN
    SELECT id, username, status, usage_seconds
      INTO v_account_id, v_account_username, v_account_status, v_usage_seconds
      FROM public.account_requests
     WHERE lower(username) = lower(v_username)
     LIMIT 1;

    IF v_account_id IS NULL OR v_account_status IS DISTINCT FROM 'approved' THEN
      RETURN jsonb_build_object('passed', false, 'invalid', true);
    END IF;

    INSERT INTO triple_v_internal.passwordless_login_sessions(account_id, username)
    VALUES (v_account_id, v_account_username)
    RETURNING token INTO v_session_token;

    UPDATE public.security_question_progress
       SET banned_until = null, updated_at = now()
     WHERE username = v_account_username;

    RETURN jsonb_build_object(
      'passed', true,
      'correct', v_correct,
      'token', v_session_token,
      'account', jsonb_build_object(
        'id', v_account_id,
        'username', v_account_username,
        'status', v_account_status,
        'usage_seconds', coalesce(v_usage_seconds, 0)
      )
    );
  END IF;

  v_banned := now() + interval '30 seconds';
  INSERT INTO public.security_question_progress(username, banned_until, updated_at)
  VALUES (v_username, v_banned, now())
  ON CONFLICT (username) DO UPDATE
     SET banned_until = excluded.banned_until, updated_at = now();

  RETURN jsonb_build_object('passed', false, 'correct', v_correct, 'banned_until', v_banned);
END;
$function$;

CREATE OR REPLACE FUNCTION public.begin_session(p_id bigint, p_password text, p_session_id text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  r public.account_requests%rowtype;
  stale boolean;
BEGIN
  SELECT * INTO r
    FROM public.account_requests
   WHERE id = p_id AND status = 'approved'
   LIMIT 1;

  IF NOT FOUND OR (
       r.password IS DISTINCT FROM p_password
       AND NOT triple_v_internal.refresh_passwordless_login_session(p_id, p_password)
     ) THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'invalid_auth_proof');
  END IF;

  stale := r.session_updated_at IS NULL OR r.session_updated_at < now() - interval '90 seconds';
  IF nullif(trim(coalesce(r.session_id, '')), '') IS NOT NULL
     AND r.session_id <> p_session_id
     AND NOT stale THEN
    RETURN jsonb_build_object('allowed', false, 'reason', 'session_in_use');
  END IF;

  UPDATE public.account_requests
     SET session_id = p_session_id, session_updated_at = now()
   WHERE id = p_id;

  RETURN jsonb_build_object('allowed', true, 'reason', 'session_started');
END;
$function$;

CREATE OR REPLACE FUNCTION public.sync_device_binding(p_id bigint, p_password text, p_fingerprint text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  r public.account_requests%rowtype;
  allowed boolean := false;
  just_bound boolean := false;
  reason text := null;
BEGIN
  SELECT * INTO r
    FROM public.account_requests
   WHERE id = p_id AND status = 'approved'
   LIMIT 1;

  IF NOT FOUND OR (
       r.password IS DISTINCT FROM p_password
       AND NOT triple_v_internal.refresh_passwordless_login_session(p_id, p_password)
     ) THEN
    RETURN jsonb_build_object('allowed', false, 'bound', false, 'just_bound', false, 'reason', 'invalid_auth_proof');
  END IF;

  IF nullif(trim(coalesce(r.device_fingerprint, '')), '') IS NULL THEN
    UPDATE public.account_requests
       SET device_fingerprint = p_fingerprint,
           device_last_seen_fp = p_fingerprint,
           device_bind_count = coalesce(device_bind_count, 0) + 1
     WHERE id = p_id;
    allowed := true;
    just_bound := true;
  ELSIF r.device_fingerprint = p_fingerprint THEN
    UPDATE public.account_requests
       SET device_last_seen_fp = p_fingerprint
     WHERE id = p_id;
    allowed := true;
  ELSE
    reason := 'device_mismatch';
  END IF;

  RETURN jsonb_build_object(
    'allowed', allowed,
    'bound', r.device_fingerprint IS NOT NULL,
    'just_bound', just_bound,
    'reason', reason
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.heartbeat_usage(p_id bigint, p_password text, p_increment bigint, p_session_id text DEFAULT NULL::text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  r public.account_requests%rowtype;
  new_usage bigint;
BEGIN
  SELECT * INTO r
    FROM public.account_requests
   WHERE id = p_id AND status = 'approved'
   LIMIT 1;

  IF NOT FOUND OR (
       r.password IS DISTINCT FROM p_password
       AND NOT triple_v_internal.refresh_passwordless_login_session(p_id, p_password)
     ) THEN
    RETURN null;
  END IF;

  IF p_session_id IS NOT NULL
     AND nullif(trim(coalesce(r.session_id, '')), '') IS NOT NULL
     AND r.session_id <> p_session_id THEN
    RETURN null;
  END IF;

  new_usage := coalesce(r.usage_seconds, 0) + greatest(coalesce(p_increment, 0), 0);
  UPDATE public.account_requests
     SET usage_seconds = new_usage, session_updated_at = now()
   WHERE id = p_id;
  RETURN new_usage;
END;
$function$;

CREATE OR REPLACE FUNCTION public.end_session(p_id bigint, p_password text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  r public.account_requests%rowtype;
BEGIN
  SELECT * INTO r FROM public.account_requests WHERE id = p_id LIMIT 1;
  IF NOT FOUND OR (
       r.password IS DISTINCT FROM p_password
       AND NOT triple_v_internal.refresh_passwordless_login_session(p_id, p_password)
     ) THEN
    RETURN jsonb_build_object('ended', false);
  END IF;

  UPDATE public.account_requests
     SET session_id = null, session_updated_at = null
   WHERE id = p_id;
  UPDATE triple_v_internal.passwordless_login_sessions
     SET revoked_at = now()
   WHERE account_id = p_id AND token::text = p_password AND revoked_at IS NULL;

  RETURN jsonb_build_object('ended', true);
END;
$function$;
