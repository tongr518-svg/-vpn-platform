ALTER TABLE node_config_approvals
    ADD COLUMN applied_at TIMESTAMPTZ;

ALTER TABLE node_config_approvals
    ADD CONSTRAINT node_config_approval_applied_requires_consumed
    CHECK (applied_at IS NULL OR consumed_at IS NOT NULL);
