-- Phase 6: face embeddings (pgvector) and per-event selfie search.
--
-- Biometric data rules:
--   * face_embeddings is readable and writable ONLY by the service role
--     (the Python worker / AI service). No browser can read it, ever.
--   * Search always covers exactly one event, and only an event that is
--     published AND has face search switched on.
--   * Selfies are never stored: the AI service computes an embedding in
--     memory, calls search_event_faces, and discards it.

create extension if not exists vector with schema extensions;

alter table public.photos
  add column faces_indexed_at timestamptz,
  add column faces_error      text;

create table public.face_embeddings (
  id          bigint generated always as identity primary key,
  photo_id    uuid not null references public.photos (id) on delete cascade,
  event_id    uuid not null references public.events (id) on delete cascade,
  embedding   extensions.vector(128) not null,   -- SFace, L2-normalised
  bbox        jsonb not null,                    -- {x, y, w, h} as fractions of the image
  det_score   real not null,
  model       text not null,
  created_at  timestamptz not null default now()
);
-- Search filters by event first, then compares every face in that event
-- (exact search: correct results, fast enough for tens of thousands of faces per event).
create index face_embeddings_event on public.face_embeddings (event_id);
create index face_embeddings_photo on public.face_embeddings (photo_id);

alter table public.face_embeddings enable row level security;  -- no policies: clients get nothing
revoke all on public.face_embeddings from anon, authenticated;

create index photos_faces_queue on public.photos (created_at) where faces_indexed_at is null and status in ('ready', 'published');

-- ---------------------------------------------------------------- consent

create table public.consent_records (
  id          bigint generated always as identity primary key,
  user_id     uuid references public.users (id) on delete set null,
  event_id    uuid references public.events (id) on delete cascade,
  type        text not null check (type in ('event_attendee_attestation', 'biometric_search', 'photographer_terms', 'tos')),
  version     text not null,
  granted_at  timestamptz not null default now(),
  revoked_at  timestamptz
);
create index consent_records_user on public.consent_records (user_id, type);

alter table public.consent_records enable row level security;
create policy "users read own consent, admins read all" on public.consent_records
  for select to authenticated using (user_id = (select auth.uid()) or public.is_admin());
revoke all on public.consent_records from anon, authenticated;
grant select on public.consent_records to authenticated;

-- Admin or the event's owner switches face search on/off. Switching it on
-- records that they confirm attendees were informed (consent attestation).
create function public.set_event_face_search(p_event_id uuid, p_enabled boolean)
returns void
language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  if not (public.is_admin() or (public.is_approved_photographer(uid) and public.is_event_owner(p_event_id, uid))) then
    raise exception 'forbidden';
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
revoke execute on function public.set_event_face_search(uuid, boolean) from public, anon;
grant execute on function public.set_event_face_search(uuid, boolean) to authenticated;

-- ---------------------------------------------------------------- worker functions (service_role only)

-- Photos that were processed but never face-indexed (new uploads are indexed
-- during processing; this queue backfills older photos or a model change).
create function public.claim_photos_for_faces(p_limit integer)
returns table (id uuid, event_id uuid, original_key text)
language sql set search_path = '' as $$
  with c as (
    select p.id from public.photos p
    where p.faces_indexed_at is null and p.status in ('ready', 'published')
      and (p.processing_locked_at is null or p.processing_locked_at < now() - interval '10 minutes')
    order by p.created_at
    limit least(greatest(coalesce(p_limit, 10), 1), 50)
    for update skip locked
  )
  update public.photos p set processing_locked_at = now()
  from c where p.id = c.id
  returning p.id, p.event_id, p.original_key;
$$;

-- Replaces all faces of one photo. p_faces: [{"embedding":[128 numbers], "bbox":{...}, "score":0.98}, ...]
create function public.save_photo_faces(p_photo_id uuid, p_model text, p_faces jsonb)
returns integer
language plpgsql set search_path = '' as $$
declare n integer;
begin
  delete from public.face_embeddings where photo_id = p_photo_id;
  insert into public.face_embeddings (photo_id, event_id, embedding, bbox, det_score, model)
  select p.id, p.event_id, (f ->> 'embedding')::extensions.vector, f -> 'bbox', (f ->> 'score')::real, p_model
  from public.photos p, jsonb_array_elements(coalesce(p_faces, '[]'::jsonb)) f
  where p.id = p_photo_id;
  get diagnostics n = row_count;
  update public.photos set face_count = n, faces_indexed_at = now(), faces_error = null, processing_locked_at = null
  where id = p_photo_id;
  return n;
end;
$$;

create function public.fail_photo_faces(p_photo_id uuid, p_error text)
returns void
language sql set search_path = '' as $$
  update public.photos set faces_indexed_at = now(), faces_error = left(p_error, 500), processing_locked_at = null
  where id = p_photo_id;
$$;

-- Selfie search inside ONE event. Returns the best-matching photos (one row
-- per photo, its closest face), most similar first. Results are possible
-- matches, not identification.
create function public.search_event_faces(p_event_id uuid, p_embedding text, p_threshold real, p_limit integer)
returns table (photo_id uuid, similarity real)
language plpgsql stable set search_path = '' as $$
#variable_conflict use_column
declare q extensions.vector(128) := p_embedding::extensions.vector;
begin
  if not exists (select 1 from public.events e where e.id = p_event_id and e.status = 'published' and e.face_search_enabled) then
    raise exception 'search_disabled';
  end if;
  return query
    select f.photo_id, max(1 - (f.embedding operator(extensions.<=>) q))::real as similarity
    from public.face_embeddings f
    join public.photos p on p.id = f.photo_id
    where f.event_id = p_event_id and p.status in ('ready', 'published')
    group by f.photo_id
    having max(1 - (f.embedding operator(extensions.<=>) q)) >= greatest(coalesce(p_threshold, 0.36), 0.2)
    order by similarity desc
    limit least(greatest(coalesce(p_limit, 100), 1), 500);
end;
$$;

revoke execute on function
  public.claim_photos_for_faces(integer),
  public.save_photo_faces(uuid, text, jsonb),
  public.fail_photo_faces(uuid, text),
  public.search_event_faces(uuid, text, real, integer)
from public, anon, authenticated;
grant execute on function
  public.claim_photos_for_faces(integer),
  public.save_photo_faces(uuid, text, jsonb),
  public.fail_photo_faces(uuid, text),
  public.search_event_faces(uuid, text, real, integer)
to service_role;
