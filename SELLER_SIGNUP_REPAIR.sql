-- BAZAAR SELLER SIGNUP REPAIR
-- Run this once in Supabase SQL Editor if seller signup shows:
-- "Database error saving new user"
-- This repair makes pending seller accounts use the safe 'staff' role
-- until the admin approves them, and makes the Auth trigger independent
-- from buyer/customer tables.

create sequence if not exists public.seller_number_seq start 1001;

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('admin','staff','seller','customer'));

create table if not exists public.seller_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  store_name text not null default 'متجري',
  full_name text,
  phone text,
  logo_url text,
  bio text,
  approved boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.seller_profiles
  add column if not exists seller_number bigint;

alter table public.seller_profiles
  add column if not exists address text;

update public.seller_profiles
set seller_number = nextval('public.seller_number_seq')
where seller_number is null;

alter table public.seller_profiles
  alter column seller_number set default nextval('public.seller_number_seq');

alter table public.seller_profiles
  alter column seller_number set not null;

create unique index if not exists seller_profiles_number_uq
  on public.seller_profiles(seller_number);

-- Replace every older version of the Auth trigger with this single version.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_type text := lower(coalesce(new.raw_user_meta_data->>'account_type','buyer'));
  v_name text := coalesce(new.raw_user_meta_data->>'full_name','');
  v_store text := coalesce(nullif(new.raw_user_meta_data->>'store_name',''),'متجري');
  v_phone text := coalesce(new.raw_user_meta_data->>'phone','');
  v_address text := coalesce(new.raw_user_meta_data->>'address','');
begin
  -- IMPORTANT: a new account is never an admin.
  -- A seller stays 'staff' until the admin approves the seller profile.
  if v_type = 'seller' then
    insert into public.profiles(id, full_name, role)
    values(new.id, v_name, 'staff')
    on conflict(id) do update
      set full_name = excluded.full_name;

    insert into public.seller_profiles(
      id, seller_number, store_name, full_name, phone, address, approved, active
    )
    values(
      new.id,
      nextval('public.seller_number_seq'),
      v_store,
      v_name,
      v_phone,
      v_address,
      false,
      true
    )
    on conflict(id) do update
      set store_name = excluded.store_name,
          full_name = excluded.full_name,
          phone = excluded.phone,
          address = excluded.address;
  else
    insert into public.profiles(id, full_name, role)
    values(new.id, v_name, 'customer')
    on conflict(id) do update
      set full_name = excluded.full_name;
  end if;

  return new;
end;
$$;

revoke all on function public.handle_new_user() from public;
grant execute on function public.handle_new_user() to postgres, service_role;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.seller_profiles enable row level security;

drop policy if exists seller_profile_self_read on public.seller_profiles;
create policy seller_profile_self_read on public.seller_profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists seller_profile_self_update on public.seller_profiles;
create policy seller_profile_self_update on public.seller_profiles
  for update to authenticated
  using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());

drop policy if exists admin_seller_profiles_all on public.seller_profiles;
create policy admin_seller_profiles_all on public.seller_profiles
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

grant select, update on public.seller_profiles to authenticated;

-- Recreate approval helper. Only an existing admin can approve a seller.
create or replace function public.approve_seller(
  p_user_id uuid,
  p_approved boolean default true
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'not authorized';
  end if;

  update public.seller_profiles
  set approved = p_approved,
      active = true,
      updated_at = now()
  where id = p_user_id;

  update public.profiles
  set role = case when p_approved then 'seller' else 'staff' end,
      updated_at = now()
  where id = p_user_id;
end;
$$;

revoke all on function public.approve_seller(uuid,boolean) from public;
grant execute on function public.approve_seller(uuid,boolean) to authenticated;
