-- Phase 15: customers need no email verification; photographers do.
--
-- Supabase's own "Confirm email" is turned off, so every new account is
-- marked confirmed by Supabase. Our own email_verified_at is set only when
-- the person types the 6-digit code we emailed (done by the website server).
-- Applying to be a photographer and accepting an invitation require it.

alter table public.users add column email_verified_at timestamptz;

-- Accounts that confirmed their email under the old setting stay verified.
update public.users u set email_verified_at = a.email_confirmed_at
from auth.users a
where a.id = u.id and a.email_confirmed_at is not null;

-- Not in the user's column update grant (full_name, phone, locale), so only
-- the server key can set it.

create or replace function public.submit_photographer_application(
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
  if not exists (select 1 from public.users where id = uid and email_verified_at is not null) then raise exception 'email_not_verified'; end if;
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

create or replace function public.accept_photographer_invitation(p_token text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  user_email text;
  inv public.photographer_invitations;
  name text;
begin
  select lower(email) into user_email from auth.users where id = uid;
  if not exists (select 1 from public.users where id = uid and email_verified_at is not null) then raise exception 'email_not_verified'; end if;

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
