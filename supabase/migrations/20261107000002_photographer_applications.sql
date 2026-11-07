-- Phase 2: photographer applications, invitations, admin approval, audit log.
--
-- Clients can READ these tables (RLS limits what they see) but can never write
-- them directly. Every write goes through a SECURITY DEFINER function below,
-- which checks who is calling, changes the rows, and writes the audit log in
-- one transaction.

create type public.photographer_status as enum ('pending', 'approved', 'rejected', 'suspended');
create type public.application_status as enum ('submitted', 'approved', 'rejected');

-- ---------------------------------------------------------------- tables

create table public.photographer_profiles (
  user_id         uuid primary key references public.users (id) on delete cascade,
  display_name    text not null check (char_length(display_name) between 2 and 80),
  bio             text check (char_length(bio) <= 2000),
  contact_email   text check (char_length(contact_email) <= 254),
  phone           text check (char_length(phone) <= 32),
  portfolio_urls  text[] not null default '{}',
  status          public.photographer_status not null default 'pending',
  source          text not null default 'application' check (source in ('application', 'invitation')),
  approved_at     timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create trigger photographer_profiles_set_updated_at
  before update on public.photographer_profiles
  for each row execute function public.set_updated_at();

create table public.photographer_applications (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references public.users (id) on delete cascade,
  display_name    text not null,
  bio             text,
  contact_email   text,
  phone           text,
  portfolio_urls  text[] not null default '{}',
  status          public.application_status not null default 'submitted',
  review_note     text check (char_length(review_note) <= 1000),
  reviewed_by     uuid references public.users (id) on delete set null,
  reviewed_at     timestamptz,
  created_at      timestamptz not null default now()
);

-- At most one open application per user.
create unique index photographer_applications_one_open
  on public.photographer_applications (user_id) where status = 'submitted';
create index photographer_applications_status_created
  on public.photographer_applications (status, created_at desc);

create table public.photographer_invitations (
  id           uuid primary key default gen_random_uuid(),
  email        text not null check (char_length(email) <= 254),
  token_hash   text not null unique,          -- sha256 of the link token; the token itself is never stored
  invited_by   uuid not null references public.users (id) on delete cascade,
  expires_at   timestamptz not null,
  accepted_by  uuid references public.users (id) on delete set null,
  accepted_at  timestamptz,
  revoked_at   timestamptz,
  created_at   timestamptz not null default now()
);

create table public.audit_logs (
  id           bigint generated always as identity primary key,
  actor_id     uuid references public.users (id) on delete set null,
  action       text not null,
  entity_type  text not null,
  entity_id    text,
  metadata     jsonb not null default '{}',
  created_at   timestamptz not null default now()
);
create index audit_logs_created on public.audit_logs (created_at desc);

-- ---------------------------------------------------------------- RLS

alter table public.photographer_profiles     enable row level security;
alter table public.photographer_applications enable row level security;
alter table public.photographer_invitations  enable row level security;
alter table public.audit_logs                enable row level security;

create policy "own or admin can read profile" on public.photographer_profiles
  for select to authenticated
  using (user_id = (select auth.uid()) or public.is_admin());

create policy "own or admin can read applications" on public.photographer_applications
  for select to authenticated
  using (user_id = (select auth.uid()) or public.is_admin());

create policy "admin can read invitations" on public.photographer_invitations
  for select to authenticated
  using (public.is_admin());

create policy "admin can read audit log" on public.audit_logs
  for select to authenticated
  using (public.is_admin());

revoke all on public.photographer_profiles, public.photographer_applications,
              public.photographer_invitations, public.audit_logs
  from anon, authenticated;
grant select on public.photographer_profiles, public.photographer_applications,
                public.photographer_invitations, public.audit_logs
  to authenticated;

-- ---------------------------------------------------------------- helpers (not callable by clients)

create function public.write_audit(p_action text, p_entity_type text, p_entity_id text, p_metadata jsonb)
returns void language sql security definer set search_path = '' as $$
  insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
  values ((select auth.uid()), p_action, p_entity_type, p_entity_id, coalesce(p_metadata, '{}'::jsonb));
$$;
revoke execute on function public.write_audit(text, text, text, jsonb) from public, anon, authenticated;

create function public.require_active_user() returns uuid
language plpgsql stable security definer set search_path = '' as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'not_authenticated'; end if;
  if not exists (select 1 from public.users where id = uid and status = 'active') then
    raise exception 'forbidden';
  end if;
  return uid;
end;
$$;
revoke execute on function public.require_active_user() from public, anon, authenticated;

create function public.require_admin() returns uuid
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  return auth.uid();
end;
$$;
revoke execute on function public.require_admin() from public, anon, authenticated;

-- ---------------------------------------------------------------- client-callable functions

-- A signed-in user applies to become a photographer.
create function public.submit_photographer_application(
  p_display_name text, p_bio text, p_contact_email text, p_phone text, p_portfolio_urls text[]
) returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  current_status public.photographer_status;
  urls text[] := coalesce(p_portfolio_urls, '{}');
  u text;
  app_id uuid;
begin
  select status into current_status from public.photographer_profiles where user_id = uid;
  if current_status in ('approved', 'suspended') then raise exception 'already_photographer'; end if;
  if exists (select 1 from public.photographer_applications where user_id = uid and status = 'submitted') then
    raise exception 'already_submitted';
  end if;

  if char_length(trim(coalesce(p_display_name, ''))) not between 2 and 80 then raise exception 'invalid_name'; end if;
  if char_length(coalesce(p_bio, '')) > 2000 then raise exception 'invalid_bio'; end if;
  if cardinality(urls) not between 1 and 5 then raise exception 'invalid_portfolio'; end if;
  foreach u in array urls loop
    if u !~ '^https://[^\s]+$' or char_length(u) > 500 then raise exception 'invalid_portfolio'; end if;
  end loop;

  insert into public.photographer_applications (user_id, display_name, bio, contact_email, phone, portfolio_urls)
  values (uid, trim(p_display_name), nullif(trim(p_bio), ''), nullif(trim(p_contact_email), ''), nullif(trim(p_phone), ''), urls)
  returning id into app_id;

  insert into public.photographer_profiles (user_id, display_name, bio, contact_email, phone, portfolio_urls, status, source)
  values (uid, trim(p_display_name), nullif(trim(p_bio), ''), nullif(trim(p_contact_email), ''), nullif(trim(p_phone), ''), urls, 'pending', 'application')
  on conflict (user_id) do update set
    display_name = excluded.display_name, bio = excluded.bio, contact_email = excluded.contact_email,
    phone = excluded.phone, portfolio_urls = excluded.portfolio_urls, status = 'pending';

  perform public.write_audit('photographer_application.submitted', 'photographer_application', app_id::text, '{}'::jsonb);
  return app_id;
end;
$$;

-- Admin approves or rejects an open application.
create function public.review_photographer_application(p_application_id uuid, p_approve boolean, p_note text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  app public.photographer_applications;
begin
  select * into app from public.photographer_applications where id = p_application_id for update;
  if not found or app.status <> 'submitted' then raise exception 'not_open'; end if;

  update public.photographer_applications
  set status = case when p_approve then 'approved' else 'rejected' end::public.application_status,
      review_note = nullif(trim(p_note), ''), reviewed_by = admin_id, reviewed_at = now()
  where id = app.id;

  if p_approve then
    update public.photographer_profiles set status = 'approved', approved_at = now() where user_id = app.user_id;
    -- Customers become photographers. Admins keep the admin role.
    update public.users set role = 'photographer' where id = app.user_id and role = 'customer';
  else
    update public.photographer_profiles set status = 'rejected' where user_id = app.user_id;
  end if;

  perform public.write_audit(
    case when p_approve then 'photographer_application.approved' else 'photographer_application.rejected' end,
    'photographer_application', app.id::text, jsonb_build_object('user_id', app.user_id, 'note', nullif(trim(p_note), '')));
end;
$$;

-- Admin suspends or reinstates an approved photographer.
create function public.set_photographer_status(p_user_id uuid, p_status public.photographer_status)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  old_status public.photographer_status;
begin
  perform public.require_admin();
  if p_status not in ('approved', 'suspended') then raise exception 'invalid_status'; end if;

  select status into old_status from public.photographer_profiles where user_id = p_user_id for update;
  if old_status is null or old_status not in ('approved', 'suspended') then raise exception 'not_photographer'; end if;
  if old_status = p_status then return; end if;

  update public.photographer_profiles set status = p_status where user_id = p_user_id;
  perform public.write_audit('photographer.status_changed', 'photographer', p_user_id::text,
    jsonb_build_object('from', old_status, 'to', p_status));
end;
$$;

-- Admin invites someone by email. Returns the one-time token for the invite link.
create function public.create_photographer_invitation(p_email text)
returns text
language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  email_clean text := lower(trim(coalesce(p_email, '')));
  token text := encode(extensions.gen_random_bytes(32), 'hex');
  inv_id uuid;
begin
  if email_clean !~ '^[^\s@]+@[^\s@]+\.[^\s@]+$' then raise exception 'invalid_email'; end if;

  insert into public.photographer_invitations (email, token_hash, invited_by, expires_at)
  values (email_clean, encode(extensions.digest(token, 'sha256'), 'hex'), admin_id, now() + interval '14 days')
  returning id into inv_id;

  perform public.write_audit('photographer_invitation.created', 'photographer_invitation', inv_id::text,
    jsonb_build_object('email', email_clean));
  return token;
end;
$$;

-- Admin cancels an unused invitation.
create function public.revoke_photographer_invitation(p_invitation_id uuid)
returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform public.require_admin();
  update public.photographer_invitations set revoked_at = now()
  where id = p_invitation_id and accepted_at is null and revoked_at is null;
  if not found then raise exception 'not_open'; end if;
  perform public.write_audit('photographer_invitation.revoked', 'photographer_invitation', p_invitation_id::text, '{}'::jsonb);
end;
$$;

-- The invited person (signed in with the invited email) accepts. They become an approved photographer.
create function public.accept_photographer_invitation(p_token text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  user_email text;
  inv public.photographer_invitations;
  name text;
begin
  select lower(email) into user_email from auth.users where id = uid;

  select * into inv from public.photographer_invitations
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
  for update;

  if not found or inv.accepted_at is not null or inv.revoked_at is not null or inv.expires_at < now() then
    raise exception 'invalid_invitation';
  end if;
  if inv.email <> user_email then raise exception 'wrong_account'; end if;

  update public.photographer_invitations set accepted_by = uid, accepted_at = now() where id = inv.id;

  select coalesce(nullif(trim(full_name), ''), split_part(user_email, '@', 1)) into name from public.users where id = uid;
  if char_length(name) < 2 then name := name || '_'; end if;

  insert into public.photographer_profiles (user_id, display_name, contact_email, status, source, approved_at)
  values (uid, left(name, 80), user_email, 'approved', 'invitation', now())
  on conflict (user_id) do update set status = 'approved', source = 'invitation', approved_at = now();

  -- Close any open application; the invitation supersedes it.
  update public.photographer_applications set status = 'approved', reviewed_by = inv.invited_by, reviewed_at = now(),
    review_note = 'Accepted invitation'
  where user_id = uid and status = 'submitted';

  update public.users set role = 'photographer' where id = uid and role = 'customer';

  perform public.write_audit('photographer_invitation.accepted', 'photographer_invitation', inv.id::text,
    jsonb_build_object('user_id', uid));
end;
$$;

-- Only signed-in users may call the public functions; each checks permissions itself.
revoke execute on function
  public.submit_photographer_application(text, text, text, text, text[]),
  public.review_photographer_application(uuid, boolean, text),
  public.set_photographer_status(uuid, public.photographer_status),
  public.create_photographer_invitation(text),
  public.revoke_photographer_invitation(uuid),
  public.accept_photographer_invitation(text)
from public, anon;
grant execute on function
  public.submit_photographer_application(text, text, text, text, text[]),
  public.review_photographer_application(uuid, boolean, text),
  public.set_photographer_status(uuid, public.photographer_status),
  public.create_photographer_invitation(text),
  public.revoke_photographer_invitation(uuid),
  public.accept_photographer_invitation(text)
to authenticated;
