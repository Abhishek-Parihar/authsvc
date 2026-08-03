# SCIM token rotation

SCIM provisioning uses long-lived bearer tokens stored hashed in Postgres (`scim_tokens`).

## Rotation procedure

1. Create a new token (admin API):

```bash
curl -X POST "$AUTHSVC_URL/v1/scim-tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id":"...","name":"provisioning-2026-08"}'
```

2. Update your IdP (Okta, Azure AD, etc.) with the new bearer token.

3. Verify SCIM:

```bash
curl "$AUTHSVC_URL/scim/v2/Users" \
  -H "Authorization: Bearer $NEW_SCIM_TOKEN"
```

4. Revoke the old token via admin API when traffic has switched.

## Cadence

- Rotate at least **annually**, or immediately on suspected compromise.
- SCIM tokens are not auto-expired; operator rotation is required.

## Related

- [account-lockdown.md](./account-lockdown.md)
- [operator-day1.md](../operator-day1.md)
