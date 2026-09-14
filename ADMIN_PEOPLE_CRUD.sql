-- BAZAAR ADMIN PEOPLE MANAGEMENT
-- Run once in Supabase SQL Editor after the existing Bazaar schema/migrations.
-- Enables admins to create/edit/delete customer records and edit/deactivate sellers.
-- Seller login accounts are created from the admin UI through Supabase Auth signUp;
-- no service_role key is placed in the browser.

begin;

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('super_admin','admin','staff','seller','customer'));

-- Customers are intentionally protected by RLS and accessed by secure RPCs.
create or replace function public.admin_list_customers()
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare r jsonb;
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  select coalesce(jsonb_agg(x order by x.created_at desc),'[]'::jsonb) into r
  from (
    select c.id,c.customer_number,c.full_name,c.phone,c.address,c.created_at,c.updated_at,c.last_order_at,
      ca.id as account_id,ca.active as account_active,
      au.email,
      (select count(*) from public.orders o where o.customer_id=c.id) as order_count,
      (select coalesce(sum(o.total),0) from public.orders o where o.customer_id=c.id and coalesce(o.status,'') <> 'cancelled') as order_total
    from public.customers c
    left join public.customer_accounts ca on ca.customer_id=c.id
    left join auth.users au on au.id=ca.id
  ) x;
  return r;
end; $$;

create or replace function public.admin_create_customer(
  p_full_name text,
  p_phone text,
  p_address text default null
)
returns jsonb
language plpgsql
security definer
set search_path=public
as $$
declare r public.customers%rowtype; v_phone text;
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  v_phone := regexp_replace(coalesce(p_phone,''),'\D','','g');
  if length(v_phone) < 7 then raise exception 'رقم الجوال غير صحيح'; end if;
  if nullif(trim(p_full_name),'') is null then raise exception 'اسم العميل مطلوب'; end if;
  insert into public.customers(full_name,phone,normalized_phone,address)
  values(trim(p_full_name),trim(p_phone),v_phone,nullif(trim(coalesce(p_address,'')),''))
  returning * into r;
  return jsonb_build_object('id',r.id,'customerNumber',r.customer_number,'fullName',r.full_name,'phone',r.phone,'address',r.address);
exception when unique_violation then
  raise exception 'يوجد عميل مسجل مسبقًا بهذا الرقم';
end; $$;

create or replace function public.admin_update_customer(
  p_id uuid,
  p_full_name text,
  p_phone text,
  p_address text default null
)
returns void
language plpgsql
security definer
set search_path=public
as $$
declare v_phone text;
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  v_phone := regexp_replace(coalesce(p_phone,''),'\D','','g');
  if length(v_phone) < 7 then raise exception 'رقم الجوال غير صحيح'; end if;
  update public.customers
  set full_name=trim(p_full_name), phone=trim(p_phone), normalized_phone=v_phone,
      address=nullif(trim(coalesce(p_address,'')),''), updated_at=now()
  where id=p_id;
  if not found then raise exception 'العميل غير موجود'; end if;
exception when unique_violation then
  raise exception 'رقم الجوال مستخدم لعميل آخر';
end; $$;

create or replace function public.admin_delete_customer(p_id uuid)
returns void
language plpgsql
security definer
set search_path=public
as $$
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  -- orders.customer_id is ON DELETE SET NULL, so historical orders are preserved.
  delete from public.customers where id=p_id;
  if not found then raise exception 'العميل غير موجود'; end if;
end; $$;

create or replace function public.admin_update_seller(
  p_user_id uuid,
  p_full_name text,
  p_store_name text,
  p_phone text,
  p_bio text default null,
  p_active boolean default true,
  p_approved boolean default false
)
returns void
language plpgsql
security definer
set search_path=public
as $$
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  update public.profiles set full_name=trim(coalesce(p_full_name,'')), updated_at=now() where id=p_user_id;
  if not exists(select 1 from public.profiles where id=p_user_id) then raise exception 'حساب البائع غير موجود'; end if;
  update public.seller_profiles
  set full_name=trim(coalesce(p_full_name,'')),store_name=coalesce(nullif(trim(p_store_name),''),'متجري'),
      phone=trim(coalesce(p_phone,'')),bio=nullif(trim(coalesce(p_bio,'')),''),
      active=p_active,approved=p_approved,updated_at=now()
  where id=p_user_id;
  update public.profiles set role=case when p_approved and p_active then 'seller' else 'staff' end,updated_at=now() where id=p_user_id;
end; $$;

create or replace function public.admin_deactivate_seller(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path=public
as $$
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  update public.seller_profiles set active=false,updated_at=now() where id=p_user_id;
  update public.profiles set role='staff',updated_at=now() where id=p_user_id;
end; $$;

create or replace function public.admin_reactivate_seller(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path=public
as $$
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  update public.seller_profiles set active=true,updated_at=now() where id=p_user_id;
  update public.profiles set role=case when (select approved from public.seller_profiles where id=p_user_id) then 'seller' else 'staff' end,updated_at=now() where id=p_user_id;
end; $$;

revoke all on function public.admin_list_customers() from public;
revoke all on function public.admin_create_customer(text,text,text) from public;
revoke all on function public.admin_update_customer(uuid,text,text,text) from public;
revoke all on function public.admin_delete_customer(uuid) from public;
revoke all on function public.admin_update_seller(uuid,text,text,text,text,boolean,boolean) from public;
revoke all on function public.admin_deactivate_seller(uuid) from public;
revoke all on function public.admin_reactivate_seller(uuid) from public;
grant execute on function public.admin_list_customers() to authenticated;
grant execute on function public.admin_create_customer(text,text,text) to authenticated;
grant execute on function public.admin_update_customer(uuid,text,text,text) to authenticated;
grant execute on function public.admin_delete_customer(uuid) to authenticated;
grant execute on function public.admin_update_seller(uuid,text,text,text,text,boolean,boolean) to authenticated;
grant execute on function public.admin_deactivate_seller(uuid) to authenticated;
grant execute on function public.admin_reactivate_seller(uuid) to authenticated;

commit;
