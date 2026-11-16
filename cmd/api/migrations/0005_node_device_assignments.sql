CREATE TABLE node_device_assignments (
    node_id     BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    device_id   BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (node_id, device_id),
    UNIQUE (device_id)
);

CREATE INDEX node_device_assignments_node_idx
    ON node_device_assignments(node_id);
