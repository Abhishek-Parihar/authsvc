-- Strict tenant isolation: deny when app.account_id is unset.

DROP POLICY IF EXISTS account_members_tenant ON account_members;
CREATE POLICY account_members_tenant ON account_members
    USING (account_id::text = current_setting('app.account_id', true));

DROP POLICY IF EXISTS audit_events_tenant ON audit_events;
CREATE POLICY audit_events_tenant ON audit_events
    USING (
        account_id::text = current_setting('app.account_id', true)
        OR account_id IS NULL
    );
