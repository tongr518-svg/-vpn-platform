ALTER TABLE nodes
    ADD COLUMN desired_config_version BIGINT NOT NULL DEFAULT 0 CHECK (desired_config_version >= 0),
    ADD COLUMN acknowledged_config_version BIGINT NOT NULL DEFAULT 0 CHECK (acknowledged_config_version >= 0),
    ADD COLUMN last_sync_at TIMESTAMPTZ,
    ADD CONSTRAINT nodes_config_ack_not_ahead
        CHECK (acknowledged_config_version <= desired_config_version);

CREATE TABLE node_config_outbox (
    id              BIGSERIAL PRIMARY KEY,
    node_id         BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    version         BIGINT NOT NULL CHECK (version > 0),
    event_type      TEXT NOT NULL CHECK (
        event_type IN ('device_assigned', 'device_unassigned', 'device_revoked')
    ),
    device_id       BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    UNIQUE (node_id, version)
);

CREATE INDEX node_config_outbox_pending_idx
    ON node_config_outbox(node_id, version)
    WHERE acknowledged_at IS NULL;

-- Carry forward assignments created before the outbox/version columns existed.
DELETE FROM node_device_assignments a
USING devices d
WHERE d.id = a.device_id AND d.revoked_at IS NOT NULL;

WITH ranked_assignments AS (
    SELECT node_id, device_id,
           row_number() OVER (PARTITION BY node_id ORDER BY device_id) AS version
    FROM node_device_assignments
)
UPDATE nodes n
SET desired_config_version = counts.max_version
FROM (
    SELECT node_id, MAX(version) AS max_version
    FROM ranked_assignments
    GROUP BY node_id
) counts
WHERE n.id = counts.node_id;

WITH ranked_assignments AS (
    SELECT node_id, device_id,
           row_number() OVER (PARTITION BY node_id ORDER BY device_id) AS version
    FROM node_device_assignments
)
INSERT INTO node_config_outbox (node_id, version, event_type, device_id)
SELECT node_id, version, 'device_assigned', device_id
FROM ranked_assignments;
