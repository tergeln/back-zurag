-- Phase 3: notifications, platform settings, admin user management, photographer profile editing.
-- Same rule as Phase 2: clients read through RLS, and every write goes through a
-- SECURITY DEFINER function that checks the caller and writes the audit log.

-- ---------------------------------------------------------------- notifications

create table public.notifications (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references public.users (id) on delete cascade,
  type        text not null,
  payload     jsonb not null default '{}',
  read_at     timestamptz,
  created_at  timestamptz not null default now()
);
create index notifications_user_created on public.notifications (user_id, created_at desc);

alter table public.notifications enable row level security;
create policy "users read own notifications" on public.notifications
  for select to authenticated using (user_id = (select auth.uid()));
revoke all on public.notifications from anon, authenticated;
grant select on public.notifications to authenticated;

create function public.notify(p_user_id uuid, p_type text, p_payload jsonb)
returns void language sql security definer set search_path = '' as $$
  insert into public.notifications (user_id, type, payload) values (p_user_id, p_type, coalesce(p_payload, '{}'::jsonb));
$$;
revoke execute on function public.notify(uuid, text, jsonb) from public, anon, authenticated;

create function public.mark_notifications_read()
returns void language plpgsql security definer set search_path = '' as $$
declare uid uuid := public.require_active_user();
begin
  update public.notifications set read_at = now() where user_id = uid and read_at is null;
end;
$$;

-- ---------------------------------------------------------------- platform settings

create table public.platform_settings (
  key         text primary key,
  value       jsonb not null,
  updated_by  uuid references public.users (id) on delete set null,
  updated_at  timestamptz not null default now()
);
insert into public.platform_settings (key, value) values
  ('commission_bp', '2000'),            -- platform share of photographer sales, in basis points (2000 = 20%)
  ('embedding_retention_days', '180');  -- face data is deleted this many days after an event

alter table public.platform_settings enable row level security;
-- Not secret: photographers see the commission rate on their dashboard.
create policy "signed-in users read settings" on public.platform_settings
  for select to authenticated using (true);
revoke all on public.platform_settings from anon, authenticated;
grant select on public.platform_settings to authenticated;

create function public.admin_update_settings(p_commission_bp integer, p_retention_days integer)
returns void language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  old_commission jsonb;
  old_retention jsonb;
begin
  if p_commission_bp is null or p_commission_bp not between 0 and 10000 then raise exception 'invalid_commission'; end if;
  if p_retention_days is null or p_retention_days not between 7 and 3650 then raise exception 'invalid_retention'; end if;

  select value into old_commission from public.platform_settings where key = 'commission_bp';
  select value into old_retention from public.platform_settings where key = 'embedding_retention_days';

  update public.platform_settings set value = to_jsonb(p_commission_bp), updated_by = admin_id, updated_at = now() where key = 'commission_bp';
  update public.platform_settings set value = to_jsonb(p_retention_days), updated_by = admin_id, updated_at = now() where key = 'embedding_retention_days';

  perform public.write_audit('settings.updated', 'platform_settings', null, jsonb_build_object(
    'commission_bp', jsonb_build_object('from', old_commission, 'to', p_commission_bp),
    'embedding_retention_days', jsonb_build_object('from', old_retention, 'to', p_retention_days)));
end;
$$;

-- ---------------------------------------------------------------- admin: users

-- Emails live in auth.users, which clients cannot read, so admins list users through this function.
create function public.admin_list_users(p_search text, p_limit integer, p_offset integer)
returns table (id uuid, email text, full_name text, role public.user_role, status public.user_status, created_at timestamptz, total bigint)
language plpgsql stable security definer set search_path = '' as $$
declare q text := '%' || coalesce(nullif(trim(p_search), ''), '') || '%';
begin
  perform public.require_admin();
  return query
    select u.id, a.email::text, u.full_name, u.role, u.status, u.created_at, count(*) over () as total
    from public.users u join auth.users a on a.id = u.id
    where a.email ilike q or coalesce(u.full_name, '') ilike q
    order by u.created_at desc
    limit least(greatest(coalesce(p_limit, 50), 1), 100) offset greatest(coalesce(p_offset, 0), 0);
end;
$$;

create function public.admin_set_user_status(p_user_id uuid, p_status public.user_status)
returns void language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  old_status public.user_status;
begin
  if p_status not in ('active', 'suspended') then raise exception 'invalid_status'; end if;
  if p_user_id = admin_id then raise exception 'cannot_change_self'; end if;

  select status into old_status from public.users where id = p_user_id for update;
  if old_status is null or old_status = 'deleted' then raise exception 'not_found'; end if;
  if old_status = p_status then return; end if;

  update public.users set status = p_status where id = p_user_id;
  perform public.write_audit('user.status_changed', 'user', p_user_id::text, jsonb_build_object('from', old_status, 'to', p_status));
  perform public.notify(p_user_id, 'account.' || p_status::text, '{}'::jsonb);
end;
$$;

-- ---------------------------------------------------------------- photographer: edit own profile

create function public.update_photographer_profile(
  p_display_name text, p_bio text, p_contact_email text, p_phone text, p_portfolio_urls text[]
) returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  current_status public.photographer_status;
  urls text[] := coalesce(p_portfolio_urls, '{}');
  u text;
begin
  select status into current_status from public.photographer_profiles where user_id = uid for update;
  -- Pending/rejected applicants change their details by applying, not here.
  if current_status is null or current_status not in ('approved', 'suspended') then raise exception 'forbidden'; end if;

  if char_length(trim(coalesce(p_display_name, ''))) not between 2 and 80 then raise exception 'invalid_name'; end if;
  if char_length(coalesce(p_bio, '')) > 2000 then raise exception 'invalid_bio'; end if;
  if cardinality(urls) > 5 then raise exception 'invalid_portfolio'; end if;
  foreach u in array urls loop
    if u !~ '^https://[^\s]+$' or char_length(u) > 500 then raise exception 'invalid_portfolio'; end if;
  end loop;

  update public.photographer_profiles set
    display_name = trim(p_display_name), bio = nullif(trim(p_bio), ''),
    contact_email = nullif(trim(p_contact_email), ''), phone = nullif(trim(p_phone), ''), portfolio_urls = urls
  where user_id = uid;

  perform public.write_audit('photographer.profile_updated', 'photographer', uid::text, '{}'::jsonb);
end;
$$;

-- ---------------------------------------------------------------- notify on Phase 2 decisions

create or replace function public.review_photographer_application(p_application_id uuid, p_approve boolean, p_note text)
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
    update public.users set role = 'photographer' where id = app.user_id and role = 'customer';
  else
    update public.photographer_profiles set status = 'rejected' where user_id = app.user_id;
  end if;

  perform public.write_audit(
    case when p_approve then 'photographer_application.approved' else 'photographer_application.rejected' end,
    'photographer_application', app.id::text, jsonb_build_object('user_id', app.user_id, 'note', nullif(trim(p_note), '')));
  perform public.notify(app.user_id,
    case when p_approve then 'application.approved' else 'application.rejected' end,
    jsonb_build_object('note', nullif(trim(p_note), '')));
end;
$$;

create or replace function public.set_photographer_status(p_user_id uuid, p_status public.photographer_status)
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
  perform public.notify(p_user_id,
    case when p_status = 'suspended' then 'photographer.suspended' else 'photographer.reinstated' end, '{}'::jsonb);
end;
$$;

-- ---------------------------------------------------------------- execute grants

revoke execute on function
  public.mark_notifications_read(),
  public.admin_update_settings(integer, integer),
  public.admin_list_users(text, integer, integer),
  public.admin_set_user_status(uuid, public.user_status),
  public.update_photographer_profile(text, text, text, text, text[])
from public, anon;
grant execute on function
  public.mark_notifications_read(),
  public.admin_update_settings(integer, integer),
  public.admin_list_users(text, integer, integer),
  public.admin_set_user_status(uuid, public.user_status),
  public.update_photographer_profile(text, text, text, text, text[])
to authenticated;
