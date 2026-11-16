ALTER TABLE nodes
    ADD COLUMN tunnel_cidr CIDR;

CREATE TABLE node_tunnel_addresses (
    node_id        BIGINT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    device_id      BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    address        INET NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('assigned', 'releasing')),
    release_version BIGINT,
    assigned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (node_id, device_id),
    CHECK (
        (state = 'assigned' AND release_version IS NULL) OR
        (state = 'releasing' AND release_version IS NOT NULL AND release_version > 0)
    )
);

CREATE UNIQUE INDEX node_tunnel_addresses_unique_node_address_idx
    ON node_tunnel_addresses(node_id, address);

CREATE UNIQUE INDEX node_tunnel_addresses_unique_device_idx
    ON node_tunnel_addresses(device_id);

CREATE INDEX node_tunnel_addresses_release_idx
    ON node_tunnel_addresses(node_id, release_version)
    WHERE state = 'releasing';
