-- Phase 10: secure downloads of purchased originals.
-- The customer never sees storage keys. The website asks authorize_download()
-- (which checks an active download right for the signed-in user), then
-- answers with a signed R2 link valid for a few minutes.

alter table public.download_access
  add column download_count      integer not null default 0,
  add column last_downloaded_at  timestamptz;

-- The signed-in customer's purchased photos (active rights only).
create function public.get_my_downloads()
returns table (photo_id uuid, filename text, width integer, height integer, bytes bigint,
               event_slug text, event_name_mn text, event_name_en text, order_no text, granted_at timestamptz, download_count integer)
language sql stable security definer set search_path = '' as $$
  select d.photo_id, p.original_filename, p.width, p.height, p.bytes, e.slug, e.name_mn, e.name_en, o.order_no, d.granted_at, d.download_count
  from public.download_access d
  join public.photos p on p.id = d.photo_id
  join public.events e on e.id = p.event_id
  join public.order_items i on i.id = d.order_item_id
  join public.orders o on o.id = i.order_id
  where d.customer_id = auth.uid() and d.revoked_at is null
  order by d.granted_at desc, p.original_filename;
$$;

-- Server-side: which of these photos may the signed-in user download right
-- now, and where are the originals? Counts the download. Max 50 per call.
create function public.authorize_download(p_photo_ids uuid[])
returns table (photo_id uuid, original_key text, filename text, mime text)
language plpgsql security definer set search_path = '' as $$
#variable_conflict use_column
declare uid uuid := public.require_active_user();
begin
  if cardinality(p_photo_ids) > 50 then raise exception 'too_many'; end if;
  return query
    with ok as (
      update public.download_access d
      set download_count = d.download_count + 1, last_downloaded_at = now()
      where d.customer_id = uid and d.revoked_at is null and d.photo_id = any (p_photo_ids)
      returning d.photo_id
    )
    select p.id, p.original_key, coalesce(nullif(p.original_filename, ''), p.id::text || '.jpg'), p.mime
    from ok join public.photos p on p.id = ok.photo_id;
    -- Deliberately no status filter: a buyer keeps their photo even if the
    -- photographer later hides or deletes it. Storage cleanup must therefore
    -- never remove originals that have download rights.
end;
$$;

revoke execute on function public.get_my_downloads(), public.authorize_download(uuid[]) from public, anon;
grant execute on function public.get_my_downloads(), public.authorize_download(uuid[]) to authenticated;
