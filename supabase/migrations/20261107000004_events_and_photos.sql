-- Phase 4: events, event participants, photos and the upload bookkeeping.
-- Files themselves live in a private Cloudflare R2 bucket. This schema only
-- records who owns what, where it is stored, and its state.

create type public.event_status as enum ('draft', 'published', 'archived');
create type public.event_visibility as enum ('public', 'private');
create type public.photo_owner_type as enum ('platform', 'photographer');
create type public.photo_status as enum ('uploading', 'processing', 'ready', 'failed', 'published', 'hidden', 'deleted');

-- ---------------------------------------------------------------- tables

create table public.events (
  id                   uuid primary key default gen_random_uuid(),
  slug                 text not null unique default lower(encode(extensions.gen_random_bytes(5), 'hex')),
  name_mn              text not null check (char_length(name_mn) between 2 and 160),
  name_en              text check (char_length(name_en) <= 160),
  description_mn       text check (char_length(description_mn) <= 4000),
  description_en       text check (char_length(description_en) <= 4000),
  event_date           date not null,
  location             text check (char_length(location) <= 200),
  cover_photo_id       uuid,                        -- FK added below (photos table comes later)
  created_by           uuid not null references public.users (id),
  status               public.event_status not null default 'draft',
  visibility           public.event_visibility not null default 'public',
  access_code_hash     text,                        -- private events (Phase 7)
  face_search_enabled  boolean not null default false,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now()
);
create trigger events_set_updated_at before update on public.events
  for each row execute function public.set_updated_at();
create index events_date on public.events (event_date desc);

create table public.event_photographers (
  event_id    uuid not null references public.events (id) on delete cascade,
  user_id     uuid not null references public.users (id) on delete cascade,
  role        text not null default 'contributor' check (role in ('owner', 'contributor')),
  added_by    uuid references public.users (id) on delete set null,
  created_at  timestamptz not null default now(),
  primary key (event_id, user_id)
);
create index event_photographers_user on public.event_photographers (user_id);

create table public.photos (
  id                 uuid primary key default gen_random_uuid(),
  event_id           uuid not null references public.events (id) on delete restrict,
  owner_type         public.photo_owner_type not null,
  owner_id           uuid references public.users (id) on delete restrict,
  uploaded_by        uuid not null references public.users (id) on delete restrict,
  original_key       text not null unique,
  preview_key        text,
  thumb_key          text,
  sha256             text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  bytes              bigint not null check (bytes > 0),
  mime               text not null,
  original_filename  text check (char_length(original_filename) <= 255),
  width              integer,
  height             integer,
  price_mnt          bigint not null check (price_mnt between 0 and 10000000),
  status             public.photo_status not null default 'uploading',
  face_count         integer,
  published_at       timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  -- Every photo has exactly one owner: the platform, or one photographer.
  constraint photos_owner check (
    (owner_type = 'platform' and owner_id is null) or (owner_type = 'photographer' and owner_id is not null)
  )
);
create trigger photos_set_updated_at before update on public.photos
  for each row execute function public.set_updated_at();
-- Duplicate detection: the same file can exist only once per event (deleted photos excluded).
create unique index photos_event_sha256 on public.photos (event_id, sha256) where status <> 'deleted';
create index photos_event_status on public.photos (event_id, status);
create index photos_owner on public.photos (owner_id, created_at desc);

alter table public.events add constraint events_cover_photo_fk
  foreign key (cover_photo_id) references public.photos (id) on delete set null;

-- ---------------------------------------------------------------- permission helpers

-- Active user + photographer role + approved photographer profile.
create function public.is_approved_photographer(p_user_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.users u join public.photographer_profiles p on p.user_id = u.id
    where u.id = p_user_id and u.status = 'active' and u.role = 'photographer' and p.status = 'approved'
  );
$$;

create function public.is_event_member(p_event_id uuid, p_user_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.event_photographers where event_id = p_event_id and user_id = p_user_id);
$$;

create function public.is_event_owner(p_event_id uuid, p_user_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.event_photographers where event_id = p_event_id and user_id = p_user_id and role = 'owner');
$$;

-- ---------------------------------------------------------------- RLS

alter table public.events enable row level security;
alter table public.event_photographers enable row level security;
alter table public.photos enable row level security;

create policy "admins and members read events" on public.events for select to authenticated
  using (public.is_admin() or public.is_event_member(id, (select auth.uid())));

create policy "admins, self and event owners read participants" on public.event_photographers for select to authenticated
  using (public.is_admin() or user_id = (select auth.uid()) or public.is_event_owner(event_id, (select auth.uid())));

create policy "admins and owners read photos" on public.photos for select to authenticated
  using (public.is_admin() or owner_id = (select auth.uid()));

revoke all on public.events, public.event_photographers, public.photos from anon, authenticated;
-- access_code_hash is never readable by clients.
grant select (id, slug, name_mn, name_en, description_mn, description_en, event_date, location, cover_photo_id,
              created_by, status, visibility, face_search_enabled, created_at, updated_at) on public.events to authenticated;
grant select on public.event_photographers, public.photos to authenticated;

-- ---------------------------------------------------------------- events

create function public.create_event(
  p_name_mn text, p_name_en text, p_description_mn text, p_description_en text,
  p_event_date date, p_location text, p_visibility public.event_visibility
) returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  ev_id uuid;
begin
  if not (public.is_admin() or public.is_approved_photographer(uid)) then raise exception 'forbidden'; end if;
  if char_length(trim(coalesce(p_name_mn, ''))) not between 2 and 160 then raise exception 'invalid_name'; end if;
  if p_event_date is null then raise exception 'invalid_date'; end if;

  insert into public.events (name_mn, name_en, description_mn, description_en, event_date, location, created_by, visibility)
  values (trim(p_name_mn), nullif(trim(p_name_en), ''), nullif(trim(p_description_mn), ''), nullif(trim(p_description_en), ''),
          p_event_date, nullif(trim(p_location), ''), uid, coalesce(p_visibility, 'public'))
  returning id into ev_id;

  -- A photographer who creates an event owns it. Admin-created events are company events.
  if not public.is_admin() then
    insert into public.event_photographers (event_id, user_id, role, added_by) values (ev_id, uid, 'owner', uid);
  end if;

  perform public.write_audit('event.created', 'event', ev_id::text, jsonb_build_object('name', trim(p_name_mn)));
  return ev_id;
end;
$$;

create function public.update_event(
  p_event_id uuid, p_name_mn text, p_name_en text, p_description_mn text, p_description_en text,
  p_event_date date, p_location text, p_visibility public.event_visibility, p_status public.event_status
) returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  old_status public.event_status;
begin
  if not (public.is_admin() or (public.is_approved_photographer(uid) and public.is_event_owner(p_event_id, uid))) then
    raise exception 'forbidden';
  end if;
  select status into old_status from public.events where id = p_event_id for update;
  if not found then raise exception 'not_found'; end if;
  if char_length(trim(coalesce(p_name_mn, ''))) not between 2 and 160 then raise exception 'invalid_name'; end if;
  if p_event_date is null then raise exception 'invalid_date'; end if;

  update public.events set
    name_mn = trim(p_name_mn), name_en = nullif(trim(p_name_en), ''),
    description_mn = nullif(trim(p_description_mn), ''), description_en = nullif(trim(p_description_en), ''),
    event_date = p_event_date, location = nullif(trim(p_location), ''),
    visibility = coalesce(p_visibility, visibility), status = coalesce(p_status, status)
  where id = p_event_id;

  perform public.write_audit('event.updated', 'event', p_event_id::text,
    jsonb_build_object('status', jsonb_build_object('from', old_status, 'to', coalesce(p_status, old_status))));
end;
$$;

-- Admin adds an approved photographer to an event (by email).
create function public.add_event_photographer(p_event_id uuid, p_email text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  target uuid;
begin
  select id into target from auth.users where lower(email) = lower(trim(coalesce(p_email, '')));
  if target is null or not public.is_approved_photographer(target) then raise exception 'not_photographer'; end if;
  if not exists (select 1 from public.events where id = p_event_id) then raise exception 'not_found'; end if;

  insert into public.event_photographers (event_id, user_id, role, added_by)
  values (p_event_id, target, 'contributor', admin_id)
  on conflict (event_id, user_id) do nothing;

  perform public.write_audit('event.photographer_added', 'event', p_event_id::text, jsonb_build_object('user_id', target));
  perform public.notify(target, 'event.added', jsonb_build_object('event_id', p_event_id));
end;
$$;

create function public.remove_event_photographer(p_event_id uuid, p_user_id uuid)
returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public.require_admin();
  delete from public.event_photographers where event_id = p_event_id and user_id = p_user_id;
  if not found then raise exception 'not_found'; end if;
  perform public.write_audit('event.photographer_removed', 'event', p_event_id::text, jsonb_build_object('user_id', p_user_id));
end;
$$;

-- ---------------------------------------------------------------- uploads

-- Step 1 of an upload batch. Validates the files, skips duplicates, and creates
-- 'uploading' photo rows. Returns one row per input file, in input order.
-- Admins upload company (platform) photos; approved event members upload their own.
create function public.create_photo_uploads(p_event_id uuid, p_files jsonb, p_price_mnt bigint)
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

-- Step 2: after the server has confirmed the files exist in storage.
create function public.mark_photos_uploaded(p_photo_ids uuid[])
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  n integer;
begin
  update public.photos set status = 'processing'
  where id = any (p_photo_ids) and uploaded_by = uid and status = 'uploading';
  get diagnostics n = row_count;
  return n;
end;
$$;

-- ---------------------------------------------------------------- photo management

-- Admins may change any photo; photographers only their own.
create function public.can_manage_photo(p_photo_id uuid, p_user_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select public.is_admin() or exists (
    select 1 from public.photos where id = p_photo_id and owner_id = p_user_id and public.is_approved_photographer(p_user_id)
  );
$$;
revoke execute on function public.can_manage_photo(uuid, uuid) from public, anon, authenticated;

create function public.update_photo_prices(p_photo_ids uuid[], p_price_mnt bigint)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  n integer;
begin
  if p_price_mnt is null or p_price_mnt not between 0 and 10000000 then raise exception 'invalid_price'; end if;
  if cardinality(p_photo_ids) > 500 then raise exception 'invalid_batch'; end if;
  if exists (select 1 from unnest(p_photo_ids) as x(id) where not public.can_manage_photo(x.id, uid)) then raise exception 'forbidden'; end if;

  update public.photos set price_mnt = p_price_mnt where id = any (p_photo_ids) and status <> 'deleted';
  get diagnostics n = row_count;
  perform public.write_audit('photos.price_changed', 'photo', null, jsonb_build_object('count', n, 'price_mnt', p_price_mnt));
  return n;
end;
$$;

-- Soft delete. The files are removed from storage by a later cleanup job.
create function public.delete_photos(p_photo_ids uuid[])
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  n integer;
begin
  if cardinality(p_photo_ids) > 500 then raise exception 'invalid_batch'; end if;
  if exists (select 1 from unnest(p_photo_ids) as x(id) where not public.can_manage_photo(x.id, uid)) then raise exception 'forbidden'; end if;

  update public.photos set status = 'deleted' where id = any (p_photo_ids) and status <> 'deleted';
  get diagnostics n = row_count;
  perform public.write_audit('photos.deleted', 'photo', null, jsonb_build_object('count', n));
  return n;
end;
$$;

-- ---------------------------------------------------------------- grants

revoke execute on function
  public.is_approved_photographer(uuid), public.is_event_member(uuid, uuid), public.is_event_owner(uuid, uuid)
from public, anon;
grant execute on function
  public.is_approved_photographer(uuid), public.is_event_member(uuid, uuid), public.is_event_owner(uuid, uuid)
to authenticated;

revoke execute on function
  public.create_event(text, text, text, text, date, text, public.event_visibility),
  public.update_event(uuid, text, text, text, text, date, text, public.event_visibility, public.event_status),
  public.add_event_photographer(uuid, text),
  public.remove_event_photographer(uuid, uuid),
  public.create_photo_uploads(uuid, jsonb, bigint),
  public.mark_photos_uploaded(uuid[]),
  public.update_photo_prices(uuid[], bigint),
  public.delete_photos(uuid[])
from public, anon;
grant execute on function
  public.create_event(text, text, text, text, date, text, public.event_visibility),
  public.update_event(uuid, text, text, text, text, date, text, public.event_visibility, public.event_status),
  public.add_event_photographer(uuid, text),
  public.remove_event_photographer(uuid, uuid),
  public.create_photo_uploads(uuid, jsonb, bigint),
  public.mark_photos_uploaded(uuid[]),
  public.update_photo_prices(uuid[], bigint),
  public.delete_photos(uuid[])
to authenticated;
