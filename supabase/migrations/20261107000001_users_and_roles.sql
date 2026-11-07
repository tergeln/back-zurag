-- Phase 1: user profiles and roles.
-- Every Supabase Auth user gets exactly one public.users row (created by trigger).
-- New users are always 'customer'. Roles are changed only by admins or via SQL;
-- clients can never set or change their own role.

create type public.user_role as enum ('customer', 'photographer', 'admin');
create type public.user_status as enum ('active', 'suspended', 'deleted');

create table public.users (
  id          uuid primary key references auth.users (id) on delete cascade,
  role        public.user_role   not null default 'customer',
  full_name   text check (char_length(full_name) <= 120),
  phone       text check (char_length(phone) <= 32),
  locale      text not null default 'mn' check (locale in ('mn', 'en')),
  status      public.user_status not null default 'active',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Keep updated_at current on every update.
create function public.set_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger users_set_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

-- Create the profile row when someone signs up.
-- Role is hard-coded to the default ('customer'); signup metadata is only
-- trusted for display name and locale.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.users (id, full_name, locale)
  values (
    new.id,
    left(new.raw_user_meta_data ->> 'full_name', 120),
    case when new.raw_user_meta_data ->> 'locale' = 'en' then 'en' else 'mn' end
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Helper for RLS policies. SECURITY DEFINER avoids recursive RLS on users.
create function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.users
    where id = (select auth.uid()) and role = 'admin' and status = 'active'
  );
$$;

-- Row level security
alter table public.users enable row level security;

create policy "users can read own profile"
  on public.users for select to authenticated
  using (id = (select auth.uid()));

create policy "admins can read all profiles"
  on public.users for select to authenticated
  using (public.is_admin());

create policy "users can update own profile"
  on public.users for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- Column-level guard: signed-in users may only edit these columns of their own row.
-- role and status are changed only by server code using the service role
-- (admin actions, checked with requireRole('admin')) or by SQL.
revoke all on public.users from anon, authenticated;
grant select on public.users to authenticated;
grant update (full_name, phone, locale) on public.users to authenticated;
