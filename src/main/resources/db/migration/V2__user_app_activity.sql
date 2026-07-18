-- ===== per-app usage (project 06 accounts dashboard) =====
-- One row per (user, client): touched on every access-token mint, so it answers
-- "which apps does this user actually use, and when last" durably — the SAS
-- oauth2_authorization table is transient and the audit trail has no client_id.

create table user_app_activity (
    user_id       uuid not null references users (id) on delete cascade,
    client_id     text not null,
    first_used_at timestamptz not null default now(),
    last_used_at  timestamptz not null default now(),
    use_count     bigint not null default 1,
    primary key (user_id, client_id)
);

create index user_app_activity_last_used_idx on user_app_activity (last_used_at desc);
