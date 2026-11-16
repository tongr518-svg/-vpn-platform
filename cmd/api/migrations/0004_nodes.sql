CREATE TABLE nodes (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    region              TEXT NOT NULL CHECK (length(btrim(region)) BETWEEN 1 AND 80),
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'maintenance', 'disabled')),
    capacity            INTEGER NOT NULL CHECK (capacity > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat_at   TIMESTAMPTZ
);

CREATE INDEX nodes_status_created_idx
    ON nodes(status, created_at DESC);

CREATE TABLE node_credentials (
    id          BIGSERIAL PRIMARY KEY,
    node_id     BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX node_credentials_node_idx
    ON node_credentials(node_id);

CREATE UNIQUE INDEX node_credentials_one_active_idx
    ON node_credentials(node_id)
    WHERE revoked_at IS NULL;
