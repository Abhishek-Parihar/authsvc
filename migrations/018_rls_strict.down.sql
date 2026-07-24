DROP POLICY IF EXISTS account_members_tenant ON account_members;
CREATE POLICY account_members_tenant ON account_members
    USING (
        account_id::text = current_setting('app.account_id', true)
        OR current_setting('app.account_id', true) = ''
        OR current_setting('app.account_id', true) IS NULL
    );

DROP POLICY IF EXISTS audit_events_tenant ON audit_events;
CREATE POLICY audit_events_tenant ON audit_events
    USING (
        account_id::text = current_setting('app.account_id', true)
        OR account_id IS NULL
        OR current_setting('app.account_id', true) = ''
        OR current_setting('app.account_id', true) IS NULL
    );
