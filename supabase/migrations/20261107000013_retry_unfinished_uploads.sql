-- Phase 13: retrying a failed upload no longer reports "duplicate".
-- If the same file is still at 'uploading' from the same uploader (e.g. the
-- browser upload to storage failed), the retry reuses that row. Anything
-- else with the same content in the event is still a duplicate.

create or replace function public.create_photo_uploads(p_event_id uuid, p_files jsonb, p_price_mnt bigint)
returns table (file_index integer, photo_id uuid, original_key text, duplicate boolean)
language plpgsql security definer set search_path = '' as $$
#variable_conflict use_column
declare
  uid uuid := public.require_active_user();
  admin boolean := public.is_admin();
  f jsonb;
  i integer := 0;
  sha text;
  new_id uuid;
  created integer := 0;
  seen text[] := '{}';
  existing record;
begin
  if not exists (select 1 from public.events where id = p_event_id and status <> 'archived') then raise exception 'not_found'; end if;
  if not (admin or (public.is_approved_photographer(uid) and public.is_event_member(p_event_id, uid))) then
    raise exception 'forbidden';
  end if;
  if jsonb_typeof(p_files) <> 'array' or jsonb_array_length(p_files) not between 1 and 100 then raise exception 'invalid_batch'; end if;
  if p_price_mnt is null or p_price_mnt not between 0 and 10000000 then raise exception 'invalid_price'; end if;
  perform public.check_upload_rate(uid, jsonb_array_length(p_files));

  for f in select * from jsonb_array_elements(p_files) loop
    sha := lower(f ->> 'sha256');
    if sha !~ '^[0-9a-f]{64}$'
       or (f ->> 'mime') not in ('image/jpeg', 'image/png', 'image/webp')
       or (f ->> 'bytes')::bigint not between 1 and 52428800 then
      raise exception 'invalid_file';
    end if;

    select p.id, p.status, p.uploaded_by, p.original_key into existing
    from public.photos p
    where p.event_id = p_event_id and p.sha256 = sha and p.status <> 'deleted'
    order by p.created_at desc limit 1;

    if sha = any (seen) or (existing.id is not null and not (existing.status = 'uploading' and existing.uploaded_by = uid)) then
      file_index := i; photo_id := null; original_key := null; duplicate := true;
      return next;
    elsif existing.id is not null then
      -- A retry of this person's own unfinished upload: hand back the same row so
      -- the file is uploaded into it, instead of reporting a duplicate.
      update public.photos set price_mnt = p_price_mnt, original_filename = left(f ->> 'filename', 255)
      where id = existing.id;
      seen := seen || sha;
      file_index := i; photo_id := existing.id; original_key := existing.original_key; duplicate := false;
      return next;
    else
      new_id := gen_random_uuid();
      insert into public.photos (id, event_id, owner_type, owner_id, uploaded_by, original_key, sha256, bytes, mime, original_filename, price_mnt)
      values (new_id, p_event_id,
              case when admin then 'platform' else 'photographer' end::public.photo_owner_type,
              case when admin then null else uid end,
              uid, 'originals/' || p_event_id || '/' || new_id, sha, (f ->> 'bytes')::bigint, f ->> 'mime',
              left(f ->> 'filename', 255), p_price_mnt);
      seen := seen || sha;
      created := created + 1;
      file_index := i; photo_id := new_id; original_key := 'originals/' || p_event_id || '/' || new_id; duplicate := false;
      return next;
    end if;
    i := i + 1;
  end loop;

  if created > 0 then
    perform public.write_audit('photos.upload_started', 'event', p_event_id::text, jsonb_build_object('count', created));
  end if;
end;
$$;
