-- Row-level security for multi-tenant isolation

ALTER TABLE account_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY account_members_tenant ON account_members
    USING (
        account_id::text = current_setting('app.account_id', true)
        OR current_setting('app.account_id', true) = ''
        OR current_setting('app.account_id', true) IS NULL
    );

CREATE POLICY audit_events_tenant ON audit_events
    USING (
        account_id::text = current_setting('app.account_id', true)
        OR account_id IS NULL
        OR current_setting('app.account_id', true) = ''
        OR current_setting('app.account_id', true) IS NULL
    );
