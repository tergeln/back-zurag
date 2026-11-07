-- Promote an existing user to admin. Run in the Supabase SQL editor.
-- The user must have signed up first. Replace the email below.
update public.users
set role = 'admin'
where id = (select id from auth.users where email = 'you@example.com');
