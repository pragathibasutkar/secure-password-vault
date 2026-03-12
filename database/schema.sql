create extension if not exists pgcrypto;

create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default timezone('utc', now())
);

create table if not exists vault (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    encrypted_data jsonb not null,
    created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_vault_user_id on vault(user_id);

create table if not exists password_reset_otps (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    otp_hash text not null,
    used boolean not null default false,
    expires_at timestamptz not null,
    created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_password_reset_otps_user_id on password_reset_otps(user_id);

create table if not exists user_master_keys (
    user_id uuid primary key references users(id) on delete cascade,
    verifier jsonb not null,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_user_master_keys_user_id on user_master_keys(user_id);

create table if not exists teams (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    created_by uuid not null references users(id) on delete cascade,
    created_at timestamptz not null default timezone('utc', now())
);

create table if not exists team_members (
    id uuid primary key default gen_random_uuid(),
    team_id uuid not null references teams(id) on delete cascade,
    user_id uuid not null references users(id) on delete cascade,
    role text not null check (role in ('admin', 'member', 'viewer')),
    created_at timestamptz not null default timezone('utc', now()),
    unique(team_id, user_id)
);

create index if not exists idx_team_members_team_user on team_members(team_id, user_id);

create table if not exists team_vault (
    id uuid primary key default gen_random_uuid(),
    team_id uuid not null references teams(id) on delete cascade,
    created_by uuid not null references users(id) on delete cascade,
    encrypted_data jsonb not null,
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_team_vault_team_id on team_vault(team_id);

create or replace function set_updated_at()
returns trigger as $$
begin
    new.updated_at = timezone('utc', now());
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_team_vault_updated_at on team_vault;
create trigger trg_team_vault_updated_at
before update on team_vault
for each row
execute function set_updated_at();

drop trigger if exists trg_user_master_keys_updated_at on user_master_keys;
create trigger trg_user_master_keys_updated_at
before update on user_master_keys
for each row
execute function set_updated_at();
