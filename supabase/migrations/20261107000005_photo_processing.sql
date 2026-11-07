-- Phase 5: processing queue for uploaded photos.
-- The Python worker (back-zurag/app) claims photos in 'processing', makes a
-- thumbnail and a watermarked preview, and marks them 'ready'. The queue is
-- the photos table itself; FOR UPDATE SKIP LOCKED lets several workers run
-- without picking the same photo. These functions are for the worker only
-- (service_role); browsers can never call them.

alter table public.photos
  add column processing_attempts  integer not null default 0,
  add column processing_error     text,
  add column processing_locked_at timestamptz;

create index photos_processing_queue on public.photos (created_at) where status = 'processing';

-- Claim up to p_limit photos. A claim older than 10 minutes counts as abandoned
-- (crashed worker) and can be claimed again.
create function public.claim_photos_for_processing(p_limit integer)
returns table (id uuid, event_id uuid, original_key text, mime text)
language sql set search_path = '' as $$
  with c as (
    select p.id from public.photos p
    where p.status = 'processing'
      and (p.processing_locked_at is null or p.processing_locked_at < now() - interval '10 minutes')
    order by p.created_at
    limit least(greatest(coalesce(p_limit, 10), 1), 50)
    for update skip locked
  )
  update public.photos p set processing_locked_at = now()
  from c where p.id = c.id
  returning p.id, p.event_id, p.original_key, p.mime;
$$;

create function public.complete_photo_processing(
  p_photo_id uuid, p_preview_key text, p_thumb_key text, p_width integer, p_height integer
) returns void
language sql set search_path = '' as $$
  update public.photos set
    status = 'ready', preview_key = p_preview_key, thumb_key = p_thumb_key,
    width = p_width, height = p_height, processing_error = null, processing_locked_at = null
  where id = p_photo_id and status = 'processing';
$$;

-- After 3 failed attempts the photo is marked 'failed' and left for a human.
create function public.fail_photo_processing(p_photo_id uuid, p_error text)
returns void
language sql set search_path = '' as $$
  update public.photos set
    processing_attempts = processing_attempts + 1,
    processing_error = left(p_error, 500),
    processing_locked_at = null,
    status = case when processing_attempts + 1 >= 3 then 'failed'::public.photo_status else status end
  where id = p_photo_id and status = 'processing';
$$;

revoke execute on function
  public.claim_photos_for_processing(integer),
  public.complete_photo_processing(uuid, text, text, integer, integer),
  public.fail_photo_processing(uuid, text)
from public, anon, authenticated;
grant execute on function
  public.claim_photos_for_processing(integer),
  public.complete_photo_processing(uuid, text, text, integer, integer),
  public.fail_photo_processing(uuid, text)
to service_role;
