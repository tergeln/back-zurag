-- Phase 12: hide/show photos, public photographer pages.

-- ---------------------------------------------------------------- 1. hide / show photos

-- Hidden photos drop out of galleries, search and carts. Buyers keep their
-- downloads (download_access ignores the photo status). Only ready photos can
-- be hidden, and only hidden ones shown again, so processing is never skipped.
create function public.set_photos_hidden(p_photo_ids uuid[], p_hidden boolean)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  n integer;
begin
  if p_hidden is null then raise exception 'invalid_batch'; end if;
  if cardinality(p_photo_ids) > 500 then raise exception 'invalid_batch'; end if;
  if exists (select 1 from unnest(p_photo_ids) as x(id) where not public.can_manage_photo(x.id, uid)) then raise exception 'forbidden'; end if;

  if p_hidden then
    update public.photos set status = 'hidden' where id = any (p_photo_ids) and status in ('ready', 'published');
  else
    update public.photos set status = 'ready' where id = any (p_photo_ids) and status = 'hidden';
  end if;
  get diagnostics n = row_count;
  perform public.write_audit(case when p_hidden then 'photos.hidden' else 'photos.shown' end, 'photo', null, jsonb_build_object('count', n));
  return n;
end;
$$;
revoke execute on function public.set_photos_hidden(uuid[], boolean) from public, anon;
grant execute on function public.set_photos_hidden(uuid[], boolean) to authenticated;

-- ---------------------------------------------------------------- 2. photographer pages

-- A random, URL-safe handle so the page address does not reveal the user id.
alter table public.photographer_profiles
  add column slug text not null unique default substr(md5(random()::text || clock_timestamp()::text), 1, 10)
  check (slug ~ '^[a-z0-9-]{3,40}$');

-- Approved photographers of active accounts: only what they chose to show
-- (name, bio, portfolio links). Contact email and phone stay private.
create function public.list_public_photographers(p_limit integer, p_offset integer)
returns table (slug text, display_name text, bio text, photo_count bigint, cover_photo_id uuid)
language sql stable security definer set search_path = '' as $$
  select pp.slug, pp.display_name, pp.bio,
         (select count(*) from public.photos p join public.events e on e.id = p.event_id
           where p.owner_id = pp.user_id and p.status in ('ready', 'published') and p.thumb_key is not null
             and e.status = 'published' and e.visibility = 'public'),
         (select p.id from public.photos p join public.events e on e.id = p.event_id
           where p.owner_id = pp.user_id and p.status in ('ready', 'published') and p.thumb_key is not null
             and e.status = 'published' and e.visibility = 'public'
           order by p.created_at desc limit 1)
  from public.photographer_profiles pp
  join public.users u on u.id = pp.user_id
  where pp.status = 'approved' and u.status = 'active'
  order by pp.approved_at desc nulls last, pp.display_name
  limit least(greatest(coalesce(p_limit, 48), 1), 100) offset greatest(coalesce(p_offset, 0), 0);
$$;

create function public.get_public_photographer(p_slug text)
returns table (slug text, display_name text, bio text, portfolio_urls text[])
language sql stable security definer set search_path = '' as $$
  select pp.slug, pp.display_name, pp.bio, pp.portfolio_urls
  from public.photographer_profiles pp
  join public.users u on u.id = pp.user_id
  where pp.slug = p_slug and pp.status = 'approved' and u.status = 'active';
$$;

-- Public, published events where this photographer has visible photos.
create function public.list_public_photographer_events(p_slug text)
returns table (id uuid, slug text, name_mn text, name_en text, event_date date, location text,
               cover_photo_id uuid, photo_count bigint)
language sql stable security definer set search_path = '' as $$
  select e.id, e.slug, e.name_mn, e.name_en, e.event_date, e.location,
         (select p.id from public.photos p where p.event_id = e.id and p.owner_id = pp.user_id
            and p.status in ('ready', 'published') and p.thumb_key is not null order by p.created_at limit 1),
         count(*)
  from public.photographer_profiles pp
  join public.users u on u.id = pp.user_id and u.status = 'active'
  join public.photos p on p.owner_id = pp.user_id and p.status in ('ready', 'published') and p.thumb_key is not null
  join public.events e on e.id = p.event_id and e.status = 'published' and e.visibility = 'public'
  where pp.slug = p_slug and pp.status = 'approved'
  group by e.id, pp.user_id
  order by e.event_date desc
  limit 100;
$$;

revoke execute on function
  public.list_public_photographers(integer, integer), public.get_public_photographer(text), public.list_public_photographer_events(text)
from public;
grant execute on function
  public.list_public_photographers(integer, integer), public.get_public_photographer(text), public.list_public_photographer_events(text)
to anon, authenticated;

-- Photo pages link to the photographer: same as before plus owner_slug (null
-- when the photographer is not approved or the photo belongs to the company).
drop function public.get_public_photos(uuid[], jsonb);
create function public.get_public_photos(p_ids uuid[], p_codes jsonb)
returns table (id uuid, price_mnt bigint, width integer, height integer, owner_name text,
               event_id uuid, event_slug text, event_name_mn text, event_name_en text, owner_slug text)
language sql stable security definer set search_path = '' as $$
  select p.id, p.price_mnt, p.width, p.height, case when p.owner_type = 'photographer' then pp.display_name end,
         e.id, e.slug, e.name_mn, e.name_en,
         case when p.owner_type = 'photographer' and pp.status = 'approved' then pp.slug end
  from public.photos p
  join public.events e on e.id = p.event_id
  left join public.photographer_profiles pp on pp.user_id = p.owner_id
  where p.id = any (p_ids[1:200]) and p.status in ('ready', 'published') and p.thumb_key is not null
    and public.can_view_event(e.id, p_codes);
$$;
revoke execute on function public.get_public_photos(uuid[], jsonb) from public;
grant execute on function public.get_public_photos(uuid[], jsonb) to anon, authenticated;
