-- Phase 14: customers see only the photos their selfie matched.
--
-- * No browsing: the event gallery function is removed. A visitor can see a
--   photo only if a selfie search in their browser matched it (last 24 hours),
--   it is in their cart, or they bought it.
-- * Searching needs no account. The browser keeps a random token in an
--   httpOnly cookie; the database stores only its SHA-256 hash.
-- * Consent is given per search (checkbox) and logged with the search.
-- * Rate limits per browser token and per network (hashed IP), checked by the
--   website server, which alone may call the search functions.
-- * An event can be published only with face search on.
-- * No photo is shown as an event or photographer cover.

-- ---------------------------------------------------------------- search log and results

alter table public.face_search_log
  alter column user_id drop not null,
  add column token_hash text,
  add column ip_hash text,
  add column consent_version text;
create index face_search_log_token_time on public.face_search_log (token_hash, created_at desc);
create index face_search_log_ip_time on public.face_search_log (ip_hash, created_at desc);

create table public.face_search_results (
  token_hash  text not null,
  photo_id    uuid not null references public.photos (id) on delete cascade,
  event_id    uuid not null references public.events (id) on delete cascade,
  similarity  real,
  created_at  timestamptz not null default now(),
  primary key (token_hash, photo_id)
);
create index face_search_results_time on public.face_search_results (created_at);
alter table public.face_search_results enable row level security;
revoke all on public.face_search_results from anon, authenticated;

-- 64 hex characters from the cookie -> stored hash; anything else -> null (sees nothing).
create function public.search_token_hash(p_token text) returns text
language sql immutable set search_path = '' as $$
  select case when p_token ~ '^[0-9a-f]{64}$' then encode(extensions.digest(p_token, 'sha256'), 'hex') end;
$$;

-- ---------------------------------------------------------------- who may see a photo

create function public.can_view_photo(p_photo_id uuid, p_token text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.photos p join public.events e on e.id = p.event_id
    where p.id = p_photo_id and p.status in ('ready', 'published') and p.thumb_key is not null
      and e.status = 'published'
      and (
        exists (select 1 from public.face_search_results r
                where r.photo_id = p.id and r.token_hash = public.search_token_hash(p_token)
                  and r.created_at > now() - interval '24 hours')
        or exists (select 1 from public.cart_items c where c.photo_id = p.id and c.user_id = (select auth.uid()))
        or exists (select 1 from public.download_access d
                   where d.photo_id = p.id and d.customer_id = (select auth.uid()) and d.revoked_at is null)
      )
  );
$$;
revoke execute on function public.can_view_photo(uuid, text) from public, anon, authenticated;

-- ---------------------------------------------------------------- public reads (replaced)

drop function public.list_public_event_photos(uuid, jsonb, integer, integer);
drop function public.get_public_photos(uuid[], jsonb);
drop function public.public_photo_image_key(uuid, text, jsonb);

create function public.get_public_photos(p_ids uuid[], p_token text)
returns table (id uuid, price_mnt bigint, width integer, height integer, owner_name text,
               event_id uuid, event_slug text, event_name_mn text, event_name_en text, owner_slug text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.price_mnt, p.width, p.height, case when p.owner_type = 'photographer' then pp.display_name end,
         e.id, e.slug, e.name_mn, e.name_en,
         case when p.owner_type = 'photographer' and pp.status = 'approved' then pp.slug end
  from public.photos p
  join public.events e on e.id = p.event_id
  left join public.photographer_profiles pp on pp.user_id = p.owner_id
  where p.id = any (p_ids[1:200]) and public.can_view_photo(p.id, p_token);
$$;

-- Storage key of a watermarked thumbnail/preview (never the original).
create function public.public_photo_image_key(p_photo_id uuid, p_variant text, p_token text)
returns text
language sql stable security definer set search_path = '' as $$
  select case when p_variant = 'preview' then p.preview_key else p.thumb_key end
  from public.photos p
  where p.id = p_photo_id and public.can_view_photo(p.id, p_token);
$$;

-- This browser's matches for one event from the last 24 hours, best first.
create function public.list_my_matches(p_event_id uuid, p_token text)
returns table (photo_id uuid, similarity real)
language sql stable security definer set search_path = '' as $$
  select r.photo_id, r.similarity from public.face_search_results r
  where r.event_id = p_event_id and r.token_hash = public.search_token_hash(p_token)
    and r.created_at > now() - interval '24 hours'
  order by r.similarity desc nulls last
  limit 200;
$$;

revoke execute on function public.get_public_photos(uuid[], text), public.public_photo_image_key(uuid, text, text),
  public.list_my_matches(uuid, text) from public;
grant execute on function public.get_public_photos(uuid[], text), public.public_photo_image_key(uuid, text, text),
  public.list_my_matches(uuid, text) to anon, authenticated;

-- No photo of people as a cover: events and photographers show no cover image.
create or replace function public.list_public_events(p_limit integer, p_offset integer)
returns table (id uuid, slug text, name_mn text, name_en text, event_date date, location text,
               face_search_enabled boolean, cover_photo_id uuid, photo_count bigint)
language sql stable security definer set search_path = '' as $$
  select e.id, e.slug, e.name_mn, e.name_en, e.event_date, e.location, e.face_search_enabled, null::uuid,
         (select count(*) from public.photos p where p.event_id = e.id and p.status in ('ready', 'published'))
  from public.events e
  where e.status = 'published' and e.visibility = 'public'
  order by e.event_date desc
  limit least(greatest(coalesce(p_limit, 24), 1), 100) offset greatest(coalesce(p_offset, 0), 0);
$$;

create or replace function public.list_public_photographers(p_limit integer, p_offset integer)
returns table (slug text, display_name text, bio text, photo_count bigint, cover_photo_id uuid)
language sql stable security definer set search_path = '' as $$
  select pp.slug, pp.display_name, pp.bio,
         (select count(*) from public.photos p join public.events e on e.id = p.event_id
           where p.owner_id = pp.user_id and p.status in ('ready', 'published') and p.thumb_key is not null
             and e.status = 'published' and e.visibility = 'public'),
         null::uuid
  from public.photographer_profiles pp
  join public.users u on u.id = pp.user_id
  where pp.status = 'approved' and u.status = 'active'
  order by pp.approved_at desc nulls last, pp.display_name
  limit least(greatest(coalesce(p_limit, 48), 1), 100) offset greatest(coalesce(p_offset, 0), 0);
$$;

create or replace function public.list_public_photographer_events(p_slug text)
returns table (id uuid, slug text, name_mn text, name_en text, event_date date, location text,
               cover_photo_id uuid, photo_count bigint)
language sql stable security definer set search_path = '' as $$
  select e.id, e.slug, e.name_mn, e.name_en, e.event_date, e.location, null::uuid, count(*)
  from public.photographer_profiles pp
  join public.users u on u.id = pp.user_id and u.status = 'active'
  join public.photos p on p.owner_id = pp.user_id and p.status in ('ready', 'published') and p.thumb_key is not null
  join public.events e on e.id = p.event_id and e.status = 'published' and e.visibility = 'public'
  where pp.slug = p_slug and pp.status = 'approved'
  group by e.id
  order by e.event_date desc
  limit 100;
$$;

-- ---------------------------------------------------------------- selfie search (website server only)

drop function public.begin_face_search(uuid, jsonb);
drop function public.finish_face_search(bigint, integer);

-- Checks the event, consent and rate limits, logs the search (never the image).
create function public.begin_face_search(p_event_id uuid, p_codes jsonb, p_token text, p_ip_hash text, p_consent boolean)
returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  th text := public.search_token_hash(p_token);
  log_id bigint;
begin
  if th is null or coalesce(p_ip_hash, '') !~ '^[0-9a-f]{64}$' then raise exception 'invalid_request'; end if;
  if not coalesce(p_consent, false) then raise exception 'no_consent'; end if;
  if not public.can_view_event(p_event_id, p_codes)
     or not exists (select 1 from public.events where id = p_event_id and face_search_enabled) then
    raise exception 'search_disabled';
  end if;
  if (select count(*) from public.face_search_log where token_hash = th and created_at > now() - interval '1 hour') >= 10
     or (select count(*) from public.face_search_log where ip_hash = p_ip_hash and created_at > now() - interval '1 hour') >= 60 then
    raise exception 'rate_limited';
  end if;
  delete from public.face_search_results where created_at < now() - interval '2 days';
  insert into public.face_search_log (user_id, event_id, token_hash, ip_hash, consent_version)
  values ((select auth.uid()), p_event_id, th, p_ip_hash, '2026-11') returning id into log_id;
  return log_id;
end;
$$;

-- Saves this search's matches for the browser (photos of the searched event only).
create function public.finish_face_search(p_log_id bigint, p_token text, p_matches jsonb)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  th text := public.search_token_hash(p_token);
  ev uuid;
  n integer;
begin
  select event_id into ev from public.face_search_log where id = p_log_id and token_hash = th;
  if ev is null then raise exception 'invalid_request'; end if;
  insert into public.face_search_results (token_hash, photo_id, event_id, similarity)
  select th, p.id, ev, (m ->> 'similarity')::real
  from jsonb_array_elements(coalesce(p_matches, '[]'::jsonb)) as m
  join public.photos p on p.id = (m ->> 'photo_id')::uuid and p.event_id = ev and p.status in ('ready', 'published')
  limit 500
  on conflict (token_hash, photo_id) do update set similarity = excluded.similarity, created_at = now();
  get diagnostics n = row_count;
  update public.face_search_log set match_count = n where id = p_log_id;
  return n;
end;
$$;

revoke execute on function public.begin_face_search(uuid, jsonb, text, text, boolean),
  public.finish_face_search(bigint, text, jsonb) from public, anon, authenticated;
grant execute on function public.begin_face_search(uuid, jsonb, text, text, boolean),
  public.finish_face_search(bigint, text, jsonb) to service_role;

-- ---------------------------------------------------------------- cart

drop function public.add_to_cart(uuid, jsonb);
create function public.add_to_cart(p_photo_id uuid, p_token text)
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not public.can_view_photo(p_photo_id, p_token) then raise exception 'not_available'; end if;
  if (select count(*) from public.cart_items where user_id = uid) >= 200 then raise exception 'cart_full'; end if;
  insert into public.cart_items (user_id, photo_id) values (uid, p_photo_id) on conflict do nothing;
end;
$$;
revoke execute on function public.add_to_cart(uuid, text) from public, anon;
grant execute on function public.add_to_cart(uuid, text) to authenticated;

-- ---------------------------------------------------------------- publishing needs face search

create or replace function public.update_event(
  p_event_id uuid, p_name_mn text, p_name_en text, p_description_mn text, p_description_en text,
  p_event_date date, p_location text, p_visibility public.event_visibility, p_status public.event_status
) returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  old_status public.event_status;
  face_on boolean;
begin
  if not (public.is_admin() or (public.is_approved_photographer(uid) and public.is_event_owner(p_event_id, uid))) then
    raise exception 'forbidden';
  end if;
  select status, face_search_enabled into old_status, face_on from public.events where id = p_event_id for update;
  if not found then raise exception 'not_found'; end if;
  if char_length(trim(coalesce(p_name_mn, ''))) not between 2 and 160 then raise exception 'invalid_name'; end if;
  if p_event_date is null then raise exception 'invalid_date'; end if;
  -- Customers find photos only by selfie, so a published event needs face search.
  if coalesce(p_status, old_status) = 'published' and not face_on then raise exception 'face_search_required'; end if;

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

create or replace function public.set_event_face_search(p_event_id uuid, p_enabled boolean)
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not (public.is_admin() or (public.is_approved_photographer(uid) and public.is_event_owner(p_event_id, uid))) then
    raise exception 'forbidden';
  end if;
  if not coalesce(p_enabled, false) and exists (select 1 from public.events where id = p_event_id and status = 'published') then
    raise exception 'unpublish_first';
  end if;
  update public.events set face_search_enabled = coalesce(p_enabled, false) where id = p_event_id;
  if not found then raise exception 'not_found'; end if;

  if p_enabled then
    insert into public.consent_records (user_id, event_id, type, version) values (uid, p_event_id, 'event_attendee_attestation', '2026-11');
  else
    update public.consent_records set revoked_at = now()
    where event_id = p_event_id and type = 'event_attendee_attestation' and revoked_at is null;
  end if;
  perform public.write_audit('event.face_search_changed', 'event', p_event_id::text, jsonb_build_object('enabled', p_enabled));
end;
$$;
