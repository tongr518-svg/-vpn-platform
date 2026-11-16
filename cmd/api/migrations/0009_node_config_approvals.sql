ALTER TABLE node_config_dry_runs
    ADD COLUMN candidate_digest TEXT NOT NULL DEFAULT '';

CREATE TABLE node_config_approvals (
    id                  BIGSERIAL PRIMARY KEY,
    node_id             BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    candidate_version   BIGINT NOT NULL CHECK (candidate_version >= 0),
    candidate_digest    TEXT NOT NULL CHECK (length(candidate_digest) = 64),
    nonce               TEXT NOT NULL UNIQUE,
    signature           BYTEA NOT NULL,
    approved_by         BIGINT NOT NULL REFERENCES users(id),
    approved_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    UNIQUE (node_id, candidate_version, candidate_digest),
    CHECK (expires_at > approved_at)
);

CREATE INDEX node_config_approvals_node_created_idx
    ON node_config_approvals(node_id, approved_at DESC);
