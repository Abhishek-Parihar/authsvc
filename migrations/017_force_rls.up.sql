-- Table owners bypass RLS unless forced; app connects as owner in dev/self-hosted.
ALTER TABLE account_members FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
