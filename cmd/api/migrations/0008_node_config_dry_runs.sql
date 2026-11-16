CREATE TABLE node_config_dry_runs (
    node_id                  BIGINT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    confirmed_version        BIGINT NOT NULL CHECK (confirmed_version >= 0),
    candidate_version        BIGINT NOT NULL CHECK (candidate_version >= 0),
    status                   TEXT NOT NULL CHECK (status IN ('valid', 'invalid')),
    added_count              INTEGER NOT NULL DEFAULT 0 CHECK (added_count >= 0),
    changed_count            INTEGER NOT NULL DEFAULT 0 CHECK (changed_count >= 0),
    removed_count            INTEGER NOT NULL DEFAULT 0 CHECK (removed_count >= 0),
    network_changed          BOOLEAN NOT NULL DEFAULT FALSE,
    validation_errors        TEXT[] NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
