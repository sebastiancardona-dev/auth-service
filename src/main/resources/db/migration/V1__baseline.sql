-- auth-service baseline.
-- Two families of tables:
--   1. Ours: users, groups, invites, audit, signing keys — the policy layer.
--   2. Spring Authorization Server's JDBC schema (oauth2_*) — the protocol layer.
--      Column shapes follow the official SAS schema scripts, adapted to Postgres
--      (text instead of blob). Do not "improve" them: JdbcOAuth2AuthorizationService
--      expects these exact names.

-- ===== identity =====

create table users (
    id            uuid primary key default gen_random_uuid(),
    email         text not null unique,
    password_hash text not null,           -- argon2id
    display_name  text not null,
    locale        text not null default 'es',
    disabled_at   timestamptz,
    created_at    timestamptz not null default now()
);

-- ecosystem-wide groups; per-app roles layer on top via user_client_roles
create table groups (
    id   text primary key,                 -- stable slug: 'admin' | 'recruiter' | 'friend'
    name text not null
);

insert into groups (id, name) values
    ('admin',     'Administrators'),
    ('recruiter', 'Recruiters — read/demo access everywhere'),
    ('friend',    'Friends — normal users');

create table user_groups (
    user_id  uuid not null references users (id) on delete cascade,
    group_id text not null references groups (id) on delete cascade,
    primary key (user_id, group_id)
);

-- per-app role overrides (claim: roles.<client_id> = [role,...])
create table user_client_roles (
    user_id   uuid not null references users (id) on delete cascade,
    client_id text not null,               -- OIDC client_id, not the surrogate id
    role      text not null,
    primary key (user_id, client_id, role)
);

-- ===== invites (registration is impossible without one) =====

create table invites (
    id         uuid primary key default gen_random_uuid(),
    token_hash text not null unique,       -- sha-256 of the token; plaintext shown once
    created_by uuid not null references users (id),
    group_id   text not null references groups (id),  -- redeemers land in this group
    expires_at timestamptz not null,
    max_uses   int not null default 1 check (max_uses >= 1),
    uses       int not null default 0 check (uses >= 0),
    note       text,                       -- admin memo: "LinkedIn recruiters wave 1"
    revoked_at timestamptz,
    created_at timestamptz not null default now()
);

create table invite_redemptions (
    id          bigint generated always as identity primary key,
    invite_id   uuid not null references invites (id),
    user_id     uuid not null references users (id),
    redeemed_at timestamptz not null default now()
);

-- ===== audit (append-only; no updates, no deletes) =====

create table audit_events (
    id         bigint generated always as identity primary key,
    at         timestamptz not null default now(),
    event      text not null,              -- LOGIN_OK, LOGIN_FAIL, INVITE_MINTED, INVITE_REDEEMED, ...
    actor_id   uuid,                       -- null for anonymous events (failed logins)
    subject    text,                       -- what it acted on (email, invite id, client id)
    detail     jsonb,
    ip         text
);

create index audit_events_at_idx on audit_events (at desc);
create index audit_events_event_idx on audit_events (event, at desc);

-- ===== JWKS key rotation =====
-- The newest active row signs; every non-expired row stays in the published JWKS
-- so tokens signed by a retiring key keep verifying until they expire.

create table signing_keys (
    id              uuid primary key default gen_random_uuid(),
    kid             text not null unique,
    private_key_pem text not null,
    public_key_pem  text not null,
    created_at      timestamptz not null default now(),
    retire_after    timestamptz not null   -- stop signing; keep publishing until + max token ttl
);

-- ===== Spring Authorization Server protocol tables (official schema, Postgres types) =====

create table oauth2_registered_client (
    id                            varchar(100) primary key,
    client_id                     varchar(100) not null,
    client_id_issued_at           timestamp default current_timestamp not null,
    client_secret                 varchar(200) default null,
    client_secret_expires_at      timestamp default null,
    client_name                   varchar(200) not null,
    client_authentication_methods varchar(1000) not null,
    authorization_grant_types     varchar(1000) not null,
    redirect_uris                 varchar(1000) default null,
    post_logout_redirect_uris     varchar(1000) default null,
    scopes                        varchar(1000) not null,
    client_settings               varchar(2000) not null,
    token_settings                varchar(2000) not null
);

create table oauth2_authorization (
    id                            varchar(100) primary key,
    registered_client_id          varchar(100) not null,
    principal_name                varchar(200) not null,
    authorization_grant_type      varchar(100) not null,
    authorized_scopes             varchar(1000) default null,
    attributes                    text default null,
    state                         varchar(500) default null,
    authorization_code_value      text default null,
    authorization_code_issued_at  timestamp default null,
    authorization_code_expires_at timestamp default null,
    authorization_code_metadata   text default null,
    access_token_value            text default null,
    access_token_issued_at        timestamp default null,
    access_token_expires_at       timestamp default null,
    access_token_metadata         text default null,
    access_token_type             varchar(100) default null,
    access_token_scopes           varchar(1000) default null,
    oidc_id_token_value           text default null,
    oidc_id_token_issued_at       timestamp default null,
    oidc_id_token_expires_at      timestamp default null,
    oidc_id_token_metadata        text default null,
    refresh_token_value           text default null,
    refresh_token_issued_at       timestamp default null,
    refresh_token_expires_at      timestamp default null,
    refresh_token_metadata        text default null,
    user_code_value               text default null,
    user_code_issued_at           timestamp default null,
    user_code_expires_at          timestamp default null,
    user_code_metadata            text default null,
    device_code_value             text default null,
    device_code_issued_at         timestamp default null,
    device_code_expires_at        timestamp default null,
    device_code_metadata          text default null
);

create table oauth2_authorization_consent (
    registered_client_id varchar(100) not null,
    principal_name       varchar(200) not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);
