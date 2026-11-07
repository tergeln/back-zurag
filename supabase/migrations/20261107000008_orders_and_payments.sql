-- Phase 8: orders, QPay payments and download access.
--
-- Rules:
--   * An order snapshots each photo's price, owner and commission when it is
--     created, so later price or commission changes never rewrite history.
--   * Only the server (service role) records invoices and confirms payments.
--     A payment is confirmed only after the server asked QPay itself
--     (payment/check) and the paid amount equals the order total. A callback
--     or a browser "success" page alone never unlocks anything.
--   * Confirming is idempotent: a repeated callback changes nothing.

create type public.order_status as enum ('pending', 'paid', 'cancelled', 'expired', 'refunded', 'partially_refunded');
create type public.payment_status as enum ('created', 'paid', 'failed', 'expired', 'cancelled', 'refunded');

create table public.orders (
  id           uuid primary key default gen_random_uuid(),
  order_no     text not null unique,
  customer_id  uuid not null references public.users (id) on delete restrict,
  total_mnt    bigint not null check (total_mnt > 0),
  status       public.order_status not null default 'pending',
  expires_at   timestamptz not null default now() + interval '30 minutes',
  paid_at      timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create trigger orders_set_updated_at before update on public.orders for each row execute function public.set_updated_at();
create index orders_customer on public.orders (customer_id, created_at desc);

create table public.order_items (
  id                  uuid primary key default gen_random_uuid(),
  order_id            uuid not null references public.orders (id) on delete cascade,
  photo_id            uuid not null references public.photos (id) on delete restrict,
  owner_type          public.photo_owner_type not null,
  owner_id            uuid references public.users (id) on delete restrict,
  price_mnt           bigint not null check (price_mnt >= 0),
  commission_bp       integer not null check (commission_bp between 0 and 10000),
  platform_fee_mnt    bigint not null check (platform_fee_mnt >= 0),
  owner_earning_mnt   bigint not null check (owner_earning_mnt >= 0),
  unique (order_id, photo_id),
  check (platform_fee_mnt + owner_earning_mnt = price_mnt)
);
create index order_items_photo on public.order_items (photo_id);
create index order_items_owner on public.order_items (owner_id);

create table public.payments (
  id                  uuid primary key default gen_random_uuid(),
  order_id            uuid not null references public.orders (id) on delete restrict,
  provider            text not null default 'qpay' check (provider = 'qpay'),
  qpay_invoice_id     text unique,
  qpay_payment_id     text unique,
  amount_mnt          bigint not null check (amount_mnt > 0),
  status              public.payment_status not null default 'created',
  qr_text             text,
  urls                jsonb not null default '[]',
  raw_check_response  jsonb,
  last_checked_at     timestamptz,
  verified_at         timestamptz,
  created_at          timestamptz not null default now()
);
create index payments_order on public.payments (order_id);

create table public.download_access (
  id             uuid primary key default gen_random_uuid(),
  customer_id    uuid not null references public.users (id) on delete cascade,
  photo_id       uuid not null references public.photos (id) on delete restrict,
  order_item_id  uuid not null references public.order_items (id) on delete restrict,
  granted_at     timestamptz not null default now(),
  revoked_at     timestamptz,
  unique (customer_id, photo_id)
);

-- ---------------------------------------------------------------- RLS: customers read their own, admins read all

alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.payments enable row level security;
alter table public.download_access enable row level security;

create policy "own or admin read orders" on public.orders for select to authenticated
  using (customer_id = (select auth.uid()) or public.is_admin());
create policy "own or admin read order items" on public.order_items for select to authenticated
  using (public.is_admin() or exists (select 1 from public.orders o where o.id = order_id and o.customer_id = (select auth.uid())));
create policy "own or admin read payments" on public.payments for select to authenticated
  using (public.is_admin() or exists (select 1 from public.orders o where o.id = order_id and o.customer_id = (select auth.uid())));
create policy "own or admin read download access" on public.download_access for select to authenticated
  using (customer_id = (select auth.uid()) or public.is_admin());

revoke all on public.orders, public.order_items, public.payments, public.download_access from anon, authenticated;
grant select on public.orders, public.order_items, public.download_access to authenticated;
-- Customers may see payment status and the QR data of their own orders, not QPay's raw answers.
grant select (id, order_id, provider, qpay_invoice_id, amount_mnt, status, qr_text, urls, verified_at, created_at) on public.payments to authenticated;

-- ---------------------------------------------------------------- customer: create an order from the cart

create function public.create_order_from_cart()
returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := public.require_active_user();
  bp integer := coalesce((select (value)::text::integer from public.platform_settings where key = 'commission_bp'), 2000);
  new_id uuid := gen_random_uuid();
  total bigint;
begin
  -- Old unpaid orders of this customer are cancelled, so only one is open at a time.
  update public.orders set status = 'cancelled' where customer_id = uid and status = 'pending';

  insert into public.orders (id, order_no, customer_id, total_mnt)
  values (new_id, 'Z' || to_char(now() at time zone 'Asia/Ulaanbaatar', 'YYMMDD') || '-' || upper(encode(extensions.gen_random_bytes(3), 'hex')), uid, 1);

  insert into public.order_items (order_id, photo_id, owner_type, owner_id, price_mnt, commission_bp, platform_fee_mnt, owner_earning_mnt)
  select new_id, p.id, p.owner_type, p.owner_id, p.price_mnt,
         case when p.owner_type = 'platform' then 10000 else bp end,
         -- The photographer's share is rounded down; the remainder (at most 1₮) goes to the platform.
         case when p.owner_type = 'platform' then p.price_mnt else p.price_mnt - (p.price_mnt * (10000 - bp)) / 10000 end,
         case when p.owner_type = 'platform' then 0 else (p.price_mnt * (10000 - bp)) / 10000 end
  from public.cart_items c
  join public.photos p on p.id = c.photo_id
  join public.events e on e.id = p.event_id
  where c.user_id = uid and p.status in ('ready', 'published') and e.status = 'published'
    and not exists (select 1 from public.download_access d where d.customer_id = uid and d.photo_id = p.id and d.revoked_at is null);

  select coalesce(sum(price_mnt), 0) into total from public.order_items where order_id = new_id;
  if total <= 0 then raise exception 'cart_empty'; end if;  -- also rolls back the order
  update public.orders set total_mnt = total where id = new_id;

  perform public.write_audit('order.created', 'order', new_id::text, jsonb_build_object('total_mnt', total));
  return new_id;
end;
$$;

-- ---------------------------------------------------------------- server only (service role)

-- After the server created the QPay invoice.
create function public.record_payment_invoice(p_order_id uuid, p_invoice_id text, p_qr_text text, p_urls jsonb)
returns uuid
language plpgsql set search_path = '' as $$
declare
  o public.orders;
  pay_id uuid;
begin
  select * into o from public.orders where id = p_order_id for update;
  if not found or o.status <> 'pending' then raise exception 'order_not_pending'; end if;
  insert into public.payments (order_id, qpay_invoice_id, amount_mnt, qr_text, urls)
  values (o.id, p_invoice_id, o.total_mnt, p_qr_text, coalesce(p_urls, '[]'::jsonb))
  returning id into pay_id;
  return pay_id;
end;
$$;

-- After the server asked QPay (payment/check) and the answer says PAID.
-- Returns 'paid' on success, 'already_paid' for a repeated confirmation,
-- 'amount_mismatch' (and unlocks nothing) when QPay's amount differs.
create function public.confirm_payment(p_invoice_id text, p_qpay_payment_id text, p_paid_amount bigint, p_raw jsonb)
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

  if pay.status = 'paid' then return 'already_paid'; end if;   -- duplicate callback: nothing to do
  if p_paid_amount is distinct from o.total_mnt or p_paid_amount is distinct from pay.amount_mnt then
    -- Kept for investigation; returning (not raising) so this record is saved.
    update public.payments set raw_check_response = p_raw, last_checked_at = now() where id = pay.id;
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
    values (null, 'payment.amount_mismatch', 'order', o.id::text, jsonb_build_object('expected', o.total_mnt, 'paid', p_paid_amount));
    return 'amount_mismatch';
  end if;
  -- A payment that arrives after the order expired or was replaced is still honoured:
  -- the customer paid the exact amount for exactly these items.

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

  insert into public.audit_logs (actor_id, action, entity_type, entity_id, metadata)
  values (null, 'order.paid', 'order', o.id::text, jsonb_build_object('amount_mnt', p_paid_amount, 'qpay_payment_id', p_qpay_payment_id));
  perform public.notify(o.customer_id, 'order.paid', jsonb_build_object('order_no', o.order_no, 'total_mnt', o.total_mnt));
  return 'paid';
end;
$$;

-- Records that QPay was asked and the invoice is not paid yet (for throttling checks).
create function public.note_payment_checked(p_invoice_id text, p_raw jsonb)
returns void
language sql set search_path = '' as $$
  update public.payments set last_checked_at = now(), raw_check_response = p_raw where qpay_invoice_id = p_invoice_id and status <> 'paid';
$$;

-- Unpaid orders past their expiry.
create function public.expire_order(p_order_id uuid)
returns void
language sql set search_path = '' as $$
  update public.orders set status = 'expired' where id = p_order_id and status = 'pending' and expires_at < now();
  update public.payments set status = 'expired' where order_id = p_order_id and status = 'created'
    and exists (select 1 from public.orders where id = p_order_id and status = 'expired');
$$;

revoke execute on function
  public.record_payment_invoice(uuid, text, text, jsonb), public.confirm_payment(text, text, bigint, jsonb),
  public.note_payment_checked(text, jsonb), public.expire_order(uuid)
from public, anon, authenticated;
grant execute on function
  public.record_payment_invoice(uuid, text, text, jsonb), public.confirm_payment(text, text, bigint, jsonb),
  public.note_payment_checked(text, jsonb), public.expire_order(uuid)
to service_role;

revoke execute on function public.create_order_from_cart() from public, anon;
grant execute on function public.create_order_from_cart() to authenticated;
