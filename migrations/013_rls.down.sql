DROP POLICY IF EXISTS audit_events_tenant ON audit_events;
DROP POLICY IF EXISTS account_members_tenant ON account_members;
ALTER TABLE audit_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE account_members DISABLE ROW LEVEL SECURITY;
