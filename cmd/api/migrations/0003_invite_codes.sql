CREATE TABLE invite_codes (
    id          BIGSERIAL PRIMARY KEY,
    code_hash   BYTEA NOT NULL UNIQUE,
    created_by  BIGINT NOT NULL REFERENCES users(id),
    max_uses    INTEGER NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses        INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    expires_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (uses <= max_uses)
);

CREATE INDEX invite_codes_created_by_idx
    ON invite_codes(created_by, created_at DESC);
