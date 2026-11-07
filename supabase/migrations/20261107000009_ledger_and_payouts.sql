-- Phase 9: commission ledger, refunds, photographer balances and payouts.
--
-- The ledger (commissions) is append-only and written only inside the
-- payment-confirmation and refund functions, so every earning is tied to a
-- verified sale. Balances are computed from the ledger and payouts on every
-- read, never stored, so they cannot drift.

-- ---------------------------------------------------------------- ledger

create table public.commissions (
  id                bigint generated always as identity primary key,
  order_item_id     uuid not null references public.order_items (id) on delete restrict,
  photographer_id   uuid references public.users (id) on delete restrict,   -- null = company photo
  type              text not null check (type in ('sale', 'refund_adjustment')),
  gross_mnt         bigint not null,   -- negative for refunds
  platform_fee_mnt  bigint not null,
  photographer_mnt  bigint not null,
  created_at        timestamptz not null default now(),
  unique (order_item_id, type),
  check (platform_fee_mnt + photographer_mnt = gross_mnt)
);
create index commissions_photographer on public.commissions (photographer_id, created_at desc);

alter table public.commissions enable row level security;
create policy "photographers read own ledger, admins all" on public.commissions for select to authenticated
  using (photographer_id = (select auth.uid()) or public.is_admin());
revoke all on public.commissions from anon, authenticated;
grant select on public.commissions to authenticated;

-- Writes the sale lines for one paid order (called inside confirm_payment).
create function public.record_sale_ledger(p_order_id uuid)
returns void
language sql set search_path = '' as $$
  insert into public.commissions (order_item_id, photographer_id, type, gross_mnt, platform_fee_mnt, photographer_mnt)
  select i.id, case when i.owner_type = 'photographer' then i.owner_id end, 'sale', i.price_mnt, i.platform_fee_mnt, i.owner_earning_mnt
  from public.order_items i join public.orders o on o.id = i.order_id
  where i.order_id = p_order_id and o.status = 'paid'
  on conflict (order_item_id, type) do nothing;
$$;
revoke execute on function public.record_sale_ledger(uuid) from public, anon, authenticated;

-- confirm_payment (Phase 8) now also writes the ledger in the same transaction.
create or replace function public.confirm_payment(p_invoice_id text, p_qpay_payment_id text, p_paid_amount bigint, p_raw jsonb)
returns text
language plpgsql set search_path = '' as $$
declare
  pay public.payments;
  o public.orders;
  item record;
begin
  select * into pay from public.payments where qpay_invoice_id = p_invoice_id for update;
  if not found then raise exception 'payment_not_found'; end if;
  select * into o from public.orders where id = pay.order_id for update;

  if pay.status = 'paid' then return 'already_paid'; end if;
  if p_paid_amount is distinct from o.total_mnt or p_paid_amount is distinct from pay.amount_mnt then
    update public.payments set raw_check_response = p_raw, last_checked_at = now() where id = pay.id;
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
    values (null, 'payment.amount_mismatch', 'order', o.id::text, jsonb_build_object('expected', o.total_mnt, 'paid', p_paid_amount));
    return 'amount_mismatch';
  end if;

  update public.payments set status = 'paid', qpay_payment_id = p_qpay_payment_id, raw_check_response = p_raw,
         verified_at = now(), last_checked_at = now()
  where id = pay.id;
  update public.orders set status = 'paid', paid_at = now() where id = o.id;

  for item in select id, photo_id from public.order_items where order_id = o.id loop
    insert into public.download_access (customer_id, photo_id, order_item_id)
    values (o.customer_id, item.photo_id, item.id)
    on conflict (customer_id, photo_id) do update set revoked_at = null, order_item_id = excluded.order_item_id, granted_at = now();
  end loop;
  delete from public.cart_items c using public.order_items i
  where i.order_id = o.id and c.user_id = o.customer_id and c.photo_id = i.photo_id;

  perform public.record_sale_ledger(o.id);

  insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
  values (null, 'order.paid', 'order', o.id::text, jsonb_build_object('amount_mnt', p_paid_amount, 'qpay_payment_id', p_qpay_payment_id));
  perform public.notify(o.customer_id, 'order.paid', jsonb_build_object('order_no', o.order_no, 'total_mnt', o.total_mnt));
  for item in select distinct owner_id from public.order_items where order_id = o.id and owner_type = 'photographer' loop
    perform public.notify(item.owner_id, 'sale.new', jsonb_build_object('order_no', o.order_no));
  end loop;
  return 'paid';
end;
$$;

-- ---------------------------------------------------------------- refunds

create table public.refunds (
  id             bigint generated always as identity primary key,
  order_id       uuid not null references public.orders (id) on delete restrict,
  order_item_id  uuid not null references public.order_items (id) on delete restrict unique,
  amount_mnt     bigint not null check (amount_mnt >= 0),
  reason         text check (char_length(reason) <= 500),
  processed_by   uuid not null references public.users (id),
  created_at     timestamptz not null default now()
);
alter table public.refunds enable row level security;
create policy "admins read refunds" on public.refunds for select to authenticated using (public.is_admin());
revoke all on public.refunds from anon, authenticated;
grant select on public.refunds to authenticated;

-- Admin records a refund of some or all items of a paid order. The money
-- itself is returned in the QPay merchant portal; this records it, reverses
-- the ledger lines and removes the customer's download rights.
create function public.admin_refund_items(p_order_id uuid, p_item_ids uuid[], p_reason text)
returns integer
language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  o public.orders;
  n integer := 0;
  item public.order_items;
begin
  select * into o from public.orders where id = p_order_id for update;
  if not found or o.status not in ('paid', 'partially_refunded') then raise exception 'not_refundable'; end if;

  for item in select * from public.order_items
              where order_id = p_order_id and id = any (p_item_ids)
                and not exists (select 1 from public.refunds r where r.order_item_id = order_items.id) loop
    insert into public.refunds (order_id, order_item_id, amount_mnt, reason, processed_by)
    values (o.id, item.id, item.price_mnt, nullif(trim(p_reason), ''), admin_id);
    insert into public.commissions (order_item_id, photographer_id, type, gross_mnt, platform_fee_mnt, photographer_mnt)
    values (item.id, case when item.owner_type = 'photographer' then item.owner_id end, 'refund_adjustment',
            -item.price_mnt, -item.platform_fee_mnt, -item.owner_earning_mnt);
    update public.download_access set revoked_at = now() where order_item_id = item.id and revoked_at is null;
    n := n + 1;
  end loop;
  if n = 0 then raise exception 'nothing_to_refund'; end if;

  update public.orders set status = case
      when (select count(*) from public.refunds where order_id = o.id) = (select count(*) from public.order_items where order_id = o.id)
      then 'refunded'::public.order_status else 'partially_refunded'::public.order_status end
  where id = o.id;
  update public.payments set status = 'refunded'
  where order_id = o.id and status = 'paid' and (select status from public.orders where id = o.id) = 'refunded';

  perform public.write_audit('order.refunded', 'order', o.id::text,
    jsonb_build_object('items', n, 'amount_mnt', (select sum(amount_mnt) from public.refunds where order_id = o.id), 'reason', nullif(trim(p_reason), '')));
  perform public.notify(o.customer_id, 'order.refunded', jsonb_build_object('order_no', o.order_no));
  return n;
end;
$$;

-- ---------------------------------------------------------------- payouts

create type public.payout_status as enum ('requested', 'approved', 'paid', 'rejected');

create table public.payouts (
  id               bigint generated always as identity primary key,
  photographer_id  uuid not null references public.users (id) on delete restrict,
  amount_mnt       bigint not null check (amount_mnt > 0),
  status           public.payout_status not null default 'requested',
  bank_name        text not null check (char_length(bank_name) between 2 and 80),
  account_number   text not null check (account_number ~ '^[0-9]{6,20}$'),
  account_holder   text not null check (char_length(account_holder) between 2 and 120),
  note             text check (char_length(note) <= 500),
  reference        text check (char_length(reference) <= 120),
  requested_at     timestamptz not null default now(),
  decided_by       uuid references public.users (id),
  decided_at       timestamptz,
  paid_at          timestamptz
);
create index payouts_photographer on public.payouts (photographer_id, requested_at desc);
create unique index payouts_one_open on public.payouts (photographer_id) where status in ('requested', 'approved');

alter table public.payouts enable row level security;
create policy "photographers read own payouts, admins all" on public.payouts for select to authenticated
  using (photographer_id = (select auth.uid()) or public.is_admin());
revoke all on public.payouts from anon, authenticated;
grant select on public.payouts to authenticated;

-- Balance = all ledger lines - paid payouts - open (requested/approved) payouts.
create function public.photographer_balance(p_user_id uuid)
returns table (earned_mnt bigint, paid_out_mnt bigint, pending_payout_mnt bigint, available_mnt bigint)
language sql stable security definer set search_path = '' as $$
  with e as (select coalesce(sum(photographer_mnt), 0)::bigint v from public.commissions where photographer_id = p_user_id),
       p as (select coalesce(sum(amount_mnt) filter (where status = 'paid'), 0)::bigint paid,
                    coalesce(sum(amount_mnt) filter (where status in ('requested', 'approved')), 0)::bigint pending
             from public.payouts where photographer_id = p_user_id)
  select e.v, p.paid, p.pending, e.v - p.paid - p.pending from e, p;
$$;
revoke execute on function public.photographer_balance(uuid) from public, anon, authenticated;

create function public.get_my_balance()
returns table (earned_mnt bigint, paid_out_mnt bigint, pending_payout_mnt bigint, available_mnt bigint)
language sql stable security definer set search_path = '' as $$
  select * from public.photographer_balance(auth.uid());
$$;

create function public.request_payout(p_amount bigint, p_bank_name text, p_account_number text, p_account_holder text)
returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  available bigint;
  new_id bigint;
begin
  if not public.is_approved_photographer(uid) then raise exception 'forbidden'; end if;
  if p_amount is null or p_amount < 10000 then raise exception 'below_minimum'; end if;
  perform pg_advisory_xact_lock(hashtext('payout:' || uid::text));  -- one request at a time per photographer
  if exists (select 1 from public.payouts where photographer_id = uid and status in ('requested', 'approved')) then
    raise exception 'already_open';
  end if;
  select b.available_mnt into available from public.photographer_balance(uid) b;
  if p_amount > available then raise exception 'insufficient_balance'; end if;

  insert into public.payouts (photographer_id, amount_mnt, bank_name, account_number, account_holder)
  values (uid, p_amount, trim(p_bank_name), regexp_replace(coalesce(p_account_number, ''), '\s', '', 'g'), trim(p_account_holder))
  returning id into new_id;
  perform public.write_audit('payout.requested', 'payout', new_id::text, jsonb_build_object('amount_mnt', p_amount));
  return new_id;
end;
$$;

create function public.admin_decide_payout(p_payout_id bigint, p_approve boolean, p_note text)
returns void
language plpgsql security definer set search_path = '' as $$
declare
  admin_id uuid := public.require_admin();
  po public.payouts;
begin
  select * into po from public.payouts where id = p_payout_id for update;
  if not found or po.status <> 'requested' then raise exception 'not_open'; end if;
  update public.payouts set status = case when p_approve then 'approved' else 'rejected' end::public.payout_status,
         decided_by = admin_id, decided_at = now(), note = nullif(trim(p_note), '')
  where id = po.id;
  perform public.write_audit(case when p_approve then 'payout.approved' else 'payout.rejected' end, 'payout', po.id::text,
    jsonb_build_object('amount_mnt', po.amount_mnt, 'note', nullif(trim(p_note), '')));
  perform public.notify(po.photographer_id, case when p_approve then 'payout.approved' else 'payout.rejected' end,
    jsonb_build_object('amount_mnt', po.amount_mnt, 'note', nullif(trim(p_note), '')));
end;
$$;

-- After the admin has actually transferred the money (bank transfer reference).
create function public.admin_mark_payout_paid(p_payout_id bigint, p_reference text)
returns void
language plpgsql security definer set search_path = '' as $$
declare po public.payouts;
begin
  perform public.require_admin();
  select * into po from public.payouts where id = p_payout_id for update;
  if not found or po.status <> 'approved' then raise exception 'not_approved'; end if;
  if char_length(trim(coalesce(p_reference, ''))) < 3 then raise exception 'reference_required'; end if;
  update public.payouts set status = 'paid', paid_at = now(), reference = trim(p_reference) where id = po.id;
  perform public.write_audit('payout.paid', 'payout', po.id::text, jsonb_build_object('amount_mnt', po.amount_mnt, 'reference', trim(p_reference)));
  perform public.notify(po.photographer_id, 'payout.paid', jsonb_build_object('amount_mnt', po.amount_mnt));
end;
$$;

-- A photographer's own ledger lines with the photo and event (no customer data).
create function public.get_my_sales(p_limit integer, p_offset integer)
returns table (id bigint, created_at timestamptz, type text, gross_mnt bigint, platform_fee_mnt bigint, photographer_mnt bigint,
               photo_id uuid, event_name_mn text, total bigint)
language sql stable security definer set search_path = '' as $$
  select c.id, c.created_at, c.type, c.gross_mnt, c.platform_fee_mnt, c.photographer_mnt, i.photo_id, e.name_mn, count(*) over ()
  from public.commissions c
  join public.order_items i on i.id = c.order_item_id
  join public.photos p on p.id = i.photo_id
  join public.events e on e.id = p.event_id
  where c.photographer_id = auth.uid()
  order by c.created_at desc, c.id desc
  limit least(greatest(coalesce(p_limit, 50), 1), 200) offset greatest(coalesce(p_offset, 0), 0);
$$;

-- ---------------------------------------------------------------- admin reporting

create function public.admin_revenue_summary(p_from date, p_to date)
returns table (orders_paid bigint, gross_mnt bigint, refunds_mnt bigint, net_mnt bigint,
               platform_mnt bigint, company_photo_mnt bigint, commission_mnt bigint, photographers_mnt bigint)
language plpgsql stable security definer set search_path = '' as $$
begin
  perform public.require_admin();
  return query
    select
      (select count(*) from public.orders o where o.paid_at::date between p_from and p_to),
      coalesce(sum(c.gross_mnt) filter (where c.type = 'sale'), 0)::bigint,
      coalesce(-sum(c.gross_mnt) filter (where c.type = 'refund_adjustment'), 0)::bigint,
      coalesce(sum(c.gross_mnt), 0)::bigint,
      coalesce(sum(c.platform_fee_mnt), 0)::bigint,
      coalesce(sum(c.platform_fee_mnt) filter (where c.photographer_id is null), 0)::bigint,
      coalesce(sum(c.platform_fee_mnt) filter (where c.photographer_id is not null), 0)::bigint,
      coalesce(sum(c.photographer_mnt), 0)::bigint
    from public.commissions c
    where (c.created_at at time zone 'Asia/Ulaanbaatar')::date between p_from and p_to;
end;
$$;

create function public.admin_photographer_balances()
returns table (photographer_id uuid, display_name text, earned_mnt bigint, paid_out_mnt bigint, pending_payout_mnt bigint, available_mnt bigint)
language plpgsql stable security definer set search_path = '' as $$
begin
  perform public.require_admin();
  return query
    select pp.user_id, pp.display_name, b.earned_mnt, b.paid_out_mnt, b.pending_payout_mnt, b.available_mnt
    from public.photographer_profiles pp, lateral public.photographer_balance(pp.user_id) b
    where pp.status in ('approved', 'suspended') or b.earned_mnt <> 0
    order by b.available_mnt desc;
end;
$$;

-- ---------------------------------------------------------------- grants

revoke execute on function
  public.get_my_sales(integer, integer),
  public.get_my_balance(), public.request_payout(bigint, text, text, text),
  public.admin_decide_payout(bigint, boolean, text), public.admin_mark_payout_paid(bigint, text),
  public.admin_refund_items(uuid, uuid[], text), public.admin_revenue_summary(date, date), public.admin_photographer_balances()
from public, anon;
grant execute on function
  public.get_my_sales(integer, integer),
  public.get_my_balance(), public.request_payout(bigint, text, text, text),
  public.admin_decide_payout(bigint, boolean, text), public.admin_mark_payout_paid(bigint, text),
  public.admin_refund_items(uuid, uuid[], text), public.admin_revenue_summary(date, date), public.admin_photographer_balances()
to authenticated;
