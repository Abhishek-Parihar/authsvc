-- Append-only audit_events for application role (production deployments).
-- Role creation requires CREATEROLE; dev databases may skip this block.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authsvc_app') THEN
        BEGIN
            CREATE ROLE authsvc_app LOGIN;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'skipping authsvc_app creation: insufficient privileges';
        END;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authsvc_app') THEN
        REVOKE UPDATE, DELETE ON audit_events FROM authsvc_app;
        GRANT SELECT, INSERT ON audit_events TO authsvc_app;
    END IF;
END
$$;

COMMENT ON TABLE audit_events IS
    'Append-only for authsvc_app: SELECT+INSERT only. Use superuser/migrator for retention jobs.';
