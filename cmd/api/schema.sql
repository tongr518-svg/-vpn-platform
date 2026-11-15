CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS devices (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL CHECK (
        platform IN ('android', 'ios', 'windows', 'macos')
    ),
    public_key   TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS devices_user_id_idx
    ON devices(user_id);

CREATE TABLE IF NOT EXISTS plans (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    device_limit     INTEGER NOT NULL DEFAULT 1,
    concurrent_limit INTEGER NOT NULL DEFAULT 1,
    data_limit_bytes BIGINT,
    speed_limit_mbps INTEGER,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (device_limit > 0),
    CHECK (concurrent_limit > 0)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id),
    plan_id    BIGINT NOT NULL REFERENCES plans(id),
    status     TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active', 'expired', 'cancelled')),
    starts_at  TIMESTAMPTZ NOT NULL,
    ends_at    TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS subscriptions_user_status_idx
    ON subscriptions(user_id, status, ends_at);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(id),
    action        TEXT NOT NULL,
    target_type   TEXT NOT NULL,
    target_id     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
