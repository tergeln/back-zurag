-- Phase 7: what customers can see and do.
--
-- Customers never read events/photos tables directly. They go through these
-- SECURITY DEFINER functions, which return only safe columns (no storage keys
-- for originals, no hashes, no owner ids) and only for events that are
-- published and either public or unlocked with the event's access code.
-- p_codes is a JSON object {event_id: code} of codes the visitor has entered.

-- ---------------------------------------------------------------- access codes

create function public.set_event_access_code(p_event_id uuid, p_code text)
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not (public.is_admin() or (public.is_approved_photographer(uid) and public.is_event_owner(p_event_id, uid))) then
    raise exception 'forbidden';
  end if;
  if p_code is not null and trim(p_code) <> '' and char_length(trim(p_code)) not between 4 and 64 then
    raise exception 'invalid_code';
  end if;
  update public.events
  set access_code_hash = case when coalesce(trim(p_code), '') = '' then null
                              else extensions.crypt(trim(p_code), extensions.gen_salt('bf')) end
  where id = p_event_id;
  if not found then raise exception 'not_found'; end if;
  perform public.write_audit('event.access_code_changed', 'event', p_event_id::text, jsonb_build_object('set', coalesce(trim(p_code), '') <> ''));
end;
$$;

-- Published, and public or unlocked with the right code.
create function public.can_view_event(p_event_id uuid, p_codes jsonb)
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.events e
    where e.id = p_event_id and e.status = 'published'
      and (e.visibility = 'public'
           or (e.access_code_hash is not null
               and coalesce(p_codes ->> e.id::text, '') <> ''
               and e.access_code_hash = extensions.crypt(p_codes ->> e.id::text, e.access_code_hash)))
  );
$$;

-- ---------------------------------------------------------------- public reads

create function public.list_public_events(p_limit integer, p_offset integer)
returns table (id uuid, slug text, name_mn text, name_en text, event_date date, location text,
               face_search_enabled boolean, cover_photo_id uuid, photo_count bigint)
language sql stable security definer set search_path = '' as $$
  select e.id, e.slug, e.name_mn, e.name_en, e.event_date, e.location, e.face_search_enabled,
         coalesce(e.cover_photo_id, (select p.id from public.photos p
                                     where p.event_id = e.id and p.status in ('ready', 'published') and p.thumb_key is not null
                                     order by p.created_at limit 1)),
         (select count(*) from public.photos p where p.event_id = e.id and p.status in ('ready', 'published'))
  from public.events e
  where e.status = 'published' and e.visibility = 'public'
  order by e.event_date desc
  limit least(greatest(coalesce(p_limit, 24), 1), 100) offset greatest(coalesce(p_offset, 0), 0);
$$;

-- A private event without the right code comes back with locked = true and no description.
create function public.get_public_event(p_slug text, p_codes jsonb)
returns table (id uuid, slug text, name_mn text, name_en text, description_mn text, description_en text,
               event_date date, location text, visibility public.event_visibility, face_search_enabled boolean,
               locked boolean, photo_count bigint)
language sql stable security definer set search_path = '' as $$
  select e.id, e.slug, e.name_mn, e.name_en,
         case when public.can_view_event(e.id, p_codes) then e.description_mn end,
         case when public.can_view_event(e.id, p_codes) then e.description_en end,
         e.event_date, e.location, e.visibility, e.face_search_enabled,
         not public.can_view_event(e.id, p_codes),
         case when public.can_view_event(e.id, p_codes)
              then (select count(*) from public.photos p where p.event_id = e.id and p.status in ('ready', 'published')) else 0 end
  from public.events e
  where e.slug = p_slug and e.status = 'published';
$$;

create function public.list_public_event_photos(p_event_id uuid, p_codes jsonb, p_limit integer, p_offset integer)
returns table (id uuid, price_mnt bigint, width integer, height integer, owner_name text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.price_mnt, p.width, p.height, case when p.owner_type = 'photographer' then pp.display_name end
  from public.photos p
  left join public.photographer_profiles pp on pp.user_id = p.owner_id
  where p.event_id = p_event_id and p.status in ('ready', 'published') and p.thumb_key is not null
    and public.can_view_event(p_event_id, p_codes)
  order by p.created_at, p.id
  limit least(greatest(coalesce(p_limit, 60), 1), 200) offset greatest(coalesce(p_offset, 0), 0);
$$;

create function public.get_public_photos(p_ids uuid[], p_codes jsonb)
returns table (id uuid, price_mnt bigint, width integer, height integer, owner_name text,
               event_id uuid, event_slug text, event_name_mn text, event_name_en text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.price_mnt, p.width, p.height, case when p.owner_type = 'photographer' then pp.display_name end,
         e.id, e.slug, e.name_mn, e.name_en
  from public.photos p
  join public.events e on e.id = p.event_id
  left join public.photographer_profiles pp on pp.user_id = p.owner_id
  where p.id = any (p_ids[1:200]) and p.status in ('ready', 'published') and p.thumb_key is not null
    and public.can_view_event(e.id, p_codes);
$$;

-- Storage key of a watermarked thumbnail/preview (never the original).
create function public.public_photo_image_key(p_photo_id uuid, p_variant text, p_codes jsonb)
returns text
language sql stable security definer set search_path = '' as $$
  select case when p_variant = 'preview' then p.preview_key else p.thumb_key end
  from public.photos p
  where p.id = p_photo_id and p.status in ('ready', 'published') and public.can_view_event(p.event_id, p_codes);
$$;

-- ---------------------------------------------------------------- selfie search gate

create table public.face_search_log (
  id           bigint generated always as identity primary key,
  user_id      uuid not null references public.users (id) on delete cascade,
  event_id     uuid not null references public.events (id) on delete cascade,
  match_count  integer,
  created_at   timestamptz not null default now()
);
create index face_search_log_user_time on public.face_search_log (user_id, created_at desc);
alter table public.face_search_log enable row level security;
create policy "admins read search log" on public.face_search_log for select to authenticated using (public.is_admin());
revoke all on public.face_search_log from anon, authenticated;
grant select on public.face_search_log to authenticated;

create function public.has_biometric_consent()
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.consent_records
                 where user_id = auth.uid() and type = 'biometric_search' and revoked_at is null);
$$;

create function public.record_biometric_consent()
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not public.has_biometric_consent() then
    insert into public.consent_records (user_id, type, version) values (uid, 'biometric_search', '2026-11');
  end if;
end;
$$;

create function public.withdraw_biometric_consent()
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  update public.consent_records set revoked_at = now()
  where user_id = uid and type = 'biometric_search' and revoked_at is null;
end;
$$;

-- Called by the website before every selfie search: checks consent, that the
-- event allows face search for this visitor, and the rate limit (10 per hour).
create function public.begin_face_search(p_event_id uuid, p_codes jsonb)
returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  log_id bigint;
begin
  if not public.has_biometric_consent() then raise exception 'no_consent'; end if;
  if not public.can_view_event(p_event_id, p_codes)
     or not exists (select 1 from public.events where id = p_event_id and face_search_enabled) then
    raise exception 'search_disabled';
  end if;
  if (select count(*) from public.face_search_log where user_id = uid and created_at > now() - interval '1 hour') >= 10 then
    raise exception 'rate_limited';
  end if;
  insert into public.face_search_log (user_id, event_id) values (uid, p_event_id) returning id into log_id;
  return log_id;
end;
$$;

create function public.finish_face_search(p_log_id bigint, p_match_count integer)
returns void
language sql security definer set search_path = '' as $$
  update public.face_search_log set match_count = p_match_count where id = p_log_id and user_id = auth.uid();
$$;

-- ---------------------------------------------------------------- cart

create table public.cart_items (
  user_id   uuid not null references public.users (id) on delete cascade,
  photo_id  uuid not null references public.photos (id) on delete cascade,
  added_at  timestamptz not null default now(),
  primary key (user_id, photo_id)
);
alter table public.cart_items enable row level security;
create policy "users read own cart" on public.cart_items for select to authenticated using (user_id = (select auth.uid()));
revoke all on public.cart_items from anon, authenticated;
grant select on public.cart_items to authenticated;

create function public.add_to_cart(p_photo_id uuid, p_codes jsonb)
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not exists (select 1 from public.photos p
                 where p.id = p_photo_id and p.status in ('ready', 'published') and public.can_view_event(p.event_id, p_codes)) then
    raise exception 'not_available';
  end if;
  if (select count(*) from public.cart_items where user_id = uid) >= 200 then raise exception 'cart_full'; end if;
  insert into public.cart_items (user_id, photo_id) values (uid, p_photo_id) on conflict do nothing;
end;
$$;

create function public.remove_from_cart(p_photo_id uuid)
returns void
language sql security definer set search_path = '' as $$
  delete from public.cart_items where user_id = auth.uid() and photo_id = p_photo_id;
$$;

-- The signed-in user's cart with current prices. A photo that was hidden,
-- deleted or whose event was unpublished shows available = false.
create function public.get_cart()
returns table (photo_id uuid, price_mnt bigint, owner_name text, event_slug text, event_name_mn text, event_name_en text,
               available boolean, added_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select c.photo_id, p.price_mnt, case when p.owner_type = 'photographer' then pp.display_name end,
         e.slug, e.name_mn, e.name_en,
         (p.status in ('ready', 'published') and e.status = 'published'), c.added_at
  from public.cart_items c
  join public.photos p on p.id = c.photo_id
  join public.events e on e.id = p.event_id
  left join public.photographer_profiles pp on pp.user_id = p.owner_id
  where c.user_id = auth.uid()
  order by c.added_at;
$$;

-- ---------------------------------------------------------------- grants

revoke execute on function
  public.can_view_event(uuid, jsonb), public.list_public_events(integer, integer), public.get_public_event(text, jsonb),
  public.list_public_event_photos(uuid, jsonb, integer, integer), public.get_public_photos(uuid[], jsonb),
  public.public_photo_image_key(uuid, text, jsonb)
from public;
grant execute on function
  public.can_view_event(uuid, jsonb), public.list_public_events(integer, integer), public.get_public_event(text, jsonb),
  public.list_public_event_photos(uuid, jsonb, integer, integer), public.get_public_photos(uuid[], jsonb),
  public.public_photo_image_key(uuid, text, jsonb)
to anon, authenticated;

revoke execute on function
  public.set_event_access_code(uuid, text), public.has_biometric_consent(), public.record_biometric_consent(),
  public.withdraw_biometric_consent(), public.begin_face_search(uuid, jsonb), public.finish_face_search(bigint, integer),
  public.add_to_cart(uuid, jsonb), public.remove_from_cart(uuid), public.get_cart()
from public, anon;
grant execute on function
  public.set_event_access_code(uuid, text), public.has_biometric_consent(), public.record_biometric_consent(),
  public.withdraw_biometric_consent(), public.begin_face_search(uuid, jsonb), public.finish_face_search(bigint, integer),
  public.add_to_cart(uuid, jsonb), public.remove_from_cart(uuid), public.get_cart()
to authenticated;
