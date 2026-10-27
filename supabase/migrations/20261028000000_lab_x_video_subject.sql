ALTER TABLE public.lab_x_content
  ADD COLUMN IF NOT EXISTS subject text;

UPDATE public.lab_x_content
SET subject = 'arabic'
WHERE content_type = 'video'
  AND (subject IS NULL OR btrim(subject) = '');

INSERT INTO public.lab_x_content
  (title, description, content_type, subject, storage_path, public_url)
SELECT
  v.title,
  'فيديو تعليمي في مادة الدراسات.',
  'video',
  'social_studies',
  'external:youtube:' || v.youtube_id,
  v.public_url
FROM (VALUES
  ('شرح دراسات 1', 'CtXE12hcYIc', 'https://youtu.be/CtXE12hcYIc?si=DQNXdOgHldgCc9Ol'),
  ('شرح دراسات 2', 'tI2FWV-ZoTY', 'https://youtu.be/tI2FWV-ZoTY?si=Vp7o7x6RlnxB8Z2g'),
  ('شرح دراسات 3', 'DnOkzidaBNA', 'https://youtu.be/DnOkzidaBNA?si=iV5na92_Vh_lUgV_'),
  ('شرح دراسات 4', '-P5u5AVWh28', 'https://youtu.be/-P5u5AVWh28?si=Ev-_F3cWeZ_Ux9ZI'),
  ('شرح دراسات 5', 'lJzy3Na_hKU', 'https://youtu.be/lJzy3Na_hKU?si=Ug8pG4UO1FIEAVTb')
) AS v(title, youtube_id, public_url)
WHERE NOT EXISTS (
  SELECT 1
  FROM public.lab_x_content AS existing
  WHERE existing.public_url = v.public_url
     OR existing.storage_path = 'external:youtube:' || v.youtube_id
);
