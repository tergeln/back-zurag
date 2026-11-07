-- Phase 11: security hardening, cleanup jobs and account deletion.

-- ---------------------------------------------------------------- 1. upload rate limit

-- Max 3000 new photo rows per uploader per hour (the uploader sends at most
-- 100 per call). Checked at the start of create_photo_uploads.
create function public.check_upload_rate(p_user_id uuid, p_new integer)
returns void
language plpgsql stable security definer set search_path = '' as $$
begin
  if (select count(*) from public.photos where uploaded_by = p_user_id and created_at > now() - interval '1 hour') + p_new > 3000 then
    raise exception 'rate_limited';
  end if;
end;
$$;
revoke execute on function public.check_upload_rate(uuid, integer) from public, anon, authenticated;

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

    if sha = any (seen) or exists (select 1 from public.photos p where p.event_id = p_event_id and p.sha256 = sha and p.status <> 'deleted') then
      file_index := i; photo_id := null; original_key := null; duplicate := true;
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

-- ---------------------------------------------------------------- 2. face data goes with the photo

-- When a photo is (soft-)deleted, its face embeddings are deleted at once.
create function public.drop_faces_of_deleted_photo() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.face_embeddings where photo_id = new.id;
  return new;
end;
$$;
create trigger photos_drop_faces_on_delete
  after update of status on public.photos
  for each row when (new.status = 'deleted' and old.status <> 'deleted')
  execute function public.drop_faces_of_deleted_photo();

delete from public.face_embeddings f using public.photos p where p.id = f.photo_id and p.status = 'deleted';

-- ---------------------------------------------------------------- 3. cleanup jobs (worker, service role)

alter table public.photos add column files_deleted_at timestamptz;

-- Uploads that never finished (24 h) or failed processing (7 days) are marked deleted.
create function public.mark_abandoned_uploads()
returns integer
language plpgsql set search_path = '' as $$
declare n integer;
begin
  update public.photos set status = 'deleted'
  where (status = 'uploading' and created_at < now() - interval '24 hours')
     or (status = 'failed' and updated_at < now() - interval '7 days');
  get diagnostics n = row_count;
  if n > 0 then
    insert into public.audit_logs (actor_id, action, entity_type, metadata) values (null, 'cleanup.abandoned_uploads', 'photo', jsonb_build_object('count', n));
  end if;
  return n;
end;
$$;

-- Deleted photos whose files can be removed from storage. A photo that a
-- customer still has an active download right for is NEVER returned.
create function public.list_deletable_photo_files(p_limit integer)
returns table (id uuid, original_key text, preview_key text, thumb_key text)
language sql stable set search_path = '' as $$
  select p.id, p.original_key, p.preview_key, p.thumb_key
  from public.photos p
  where p.status = 'deleted' and p.files_deleted_at is null and p.updated_at < now() - interval '1 hour'
    and not exists (select 1 from public.download_access d where d.photo_id = p.id and d.revoked_at is null)
  order by p.updated_at
  limit least(greatest(coalesce(p_limit, 100), 1), 500);
$$;

create function public.mark_photo_files_deleted(p_photo_ids uuid[])
returns integer
language plpgsql set search_path = '' as $$
declare n integer;
begin
  update public.photos set files_deleted_at = now()
  where id = any (p_photo_ids) and status = 'deleted'
    and not exists (select 1 from public.download_access d where d.photo_id = photos.id and d.revoked_at is null);
  get diagnostics n = row_count;
  return n;
end;
$$;

-- Face data of events older than the retention period is deleted and face
-- search for those events is switched off.
create function public.expire_face_data()
returns integer
language plpgsql set search_path = '' as $$
declare
  days integer := coalesce((select (value)::text::integer from public.platform_settings where key = 'embedding_retention_days'), 180);
  ev record;
  n integer;
  total integer := 0;
begin
  for ev in select e.id from public.events e
            where e.event_date + days < (now() at time zone 'Asia/Ulaanbaatar')::date
              and (e.face_search_enabled or exists (select 1 from public.face_embeddings f where f.event_id = e.id)) loop
    delete from public.face_embeddings where event_id = ev.id;
    get diagnostics n = row_count;
    update public.events set face_search_enabled = false where id = ev.id;
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
    values (null, 'cleanup.face_data_expired', 'event', ev.id::text, jsonb_build_object('faces', n, 'retention_days', days));
    total := total + n;
  end loop;
  return total;
end;
$$;

revoke execute on function
  public.mark_abandoned_uploads(), public.list_deletable_photo_files(integer),
  public.mark_photo_files_deleted(uuid[]), public.expire_face_data()
from public, anon, authenticated;
grant execute on function
  public.mark_abandoned_uploads(), public.list_deletable_photo_files(integer),
  public.mark_photo_files_deleted(uuid[]), public.expire_face_data()
to service_role;

-- ---------------------------------------------------------------- 4. account deletion

-- Removes the user's personal data. Orders and payments are kept for
-- accounting (they only reference the anonymous user id). The website then
-- blocks the login and replaces the email (Supabase Auth admin API).
create function public.delete_my_account()
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if public.is_admin() then raise exception 'admin_cannot_delete'; end if;
  if exists (select 1 from public.photographer_profiles where user_id = uid and status in ('approved', 'suspended')) then
    raise exception 'photographer_contact_admin';  -- photos, earnings and payouts need an admin
  end if;

  update public.users set status = 'deleted', full_name = null, phone = null where id = uid;
  delete from public.cart_items where user_id = uid;
  delete from public.notifications where user_id = uid;
  delete from public.face_search_log where user_id = uid;
  delete from public.photographer_applications where user_id = uid;
  delete from public.photographer_profiles where user_id = uid;
  update public.consent_records set revoked_at = coalesce(revoked_at, now()) where user_id = uid;
  update public.download_access set revoked_at = coalesce(revoked_at, now()) where customer_id = uid;
  update public.orders set status = 'cancelled' where customer_id = uid and status = 'pending';
  perform public.write_audit('user.deleted_self', 'user', uid::text, '{}'::jsonb);
end;
$$;
revoke execute on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;
