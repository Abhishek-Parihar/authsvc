# SAML in authsvc

## Overview

authsvc supports SAML in two modes:

1. **Service Provider (SP)** — federate users *from* external IdPs (Okta, Azure AD, etc.) into authsvc.
2. **Identity Provider (IdP)** — act as a central IdP for downstream SAML applications (relying parties).

OIDC remains the recommended default for new integrations; use SAML when an IdP or legacy app requires it.

## SP mode (federate into authsvc)

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | SP metadata XML (ACS + SLO) |
| `/saml/login` | GET | SP-initiated SSO redirect |
| `/saml/acs` | POST | Assertion Consumer Service callback |
| `/saml/slo` | GET/POST | Single Logout (LogoutRequest / LogoutResponse) |
| `/saml/logout` | GET | SP-initiated logout redirect |

### Features

- **AuthnRequest generation** — real SAML 2.0 XML with `ID`, `IssueInstant`, ACS URL, and `NameIDPolicy`
- **HTTP-Redirect binding** — DEFLATE + base64 URL encoding per SAML spec
- **SP request signing** — optional XMLDSig when `sp_private_key_pem` is configured
- **Response validation** — `Success` status, `NotOnOrAfter` expiry, `InResponseTo` correlation
- **IdP signature verification** — XMLDSig RSA/ECDSA via `xml-sec` when `idp_cert_pem` is set
- **Encrypted assertions** — decrypt with SP private key (`encryption` feature, enabled by default)
- **IdP-initiated SSO** — set `unsolicited: true` to accept responses without `InResponseTo`
- **Single Logout (SLO)** — `SingleLogoutService` in metadata; `/saml/slo` and `/saml/logout` handlers

### Configuration

Store in `account_idp_configs.config_json`:

```json
{
  "type": "saml",
  "provider": "okta",
  "idp_sso_url": "https://your-idp.example/sso",
  "idp_slo_url": "https://your-idp.example/slo",
  "sp_entity_id": "https://auth.example.com",
  "idp_cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "sp_private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "require_signature": true,
  "unsolicited": false
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `idp_sso_url` | yes | IdP SSO URL |
| `idp_cert_pem` | recommended | IdP signing certificate (PEM) for response verification |
| `sp_entity_id` | no | Defaults to `ISSUER` |
| `sp_private_key_pem` | no | SP key for AuthnRequest signing and encrypted assertion decryption |
| `idp_slo_url` | no | IdP SLO URL (required for SP-initiated logout) |
| `require_signature` | no | Default `true` when `idp_cert_pem` is set |
| `unsolicited` | no | Allow IdP-initiated SSO without `InResponseTo` (default `false`) |

### Relay state

SP-initiated login encodes relay state as `{federation_state}|{authn_request_id}`. The ACS handler splits this to validate `InResponseTo` against the original AuthnRequest `ID`.

## IdP mode (authsvc as central IdP)

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/idp/metadata` | GET | IdP metadata XML |
| `/saml/idp/sso` | GET/POST | SSO entry (HTTP-Redirect / HTTP-POST binding) |
| `/saml/idp/login` | POST | Complete login after hosted UI (returns POST binding HTML) |
| `/login?saml_authn_id=…` | GET | Hosted login page for pending AuthnRequest |

### Register a service provider

Admin API (requires bootstrap secret or admin JWT):

```bash
curl -X POST "$ISSUER/v1/saml/service-providers" \
  -H "Authorization: Bearer $BOOTSTRAP_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "entity_id": "https://app.example.com",
    "acs_url": "https://app.example.com/saml/acs",
    "want_authn_requests_signed": false
  }'
```

Or use the **Admin console** at `/admin` → SAML service providers.

### SP configuration

1. Publish IdP metadata from `GET /saml/idp/metadata` to your relying party.
2. Set **Entity ID** to your `ISSUER` value.
3. Register the SP's **Entity ID** and **ACS URL** in authsvc (see above).
4. Signing uses the active JWT RSA key (same as OIDC JWKS).

### Flow

1. SP sends `AuthnRequest` to `/saml/idp/sso`.
2. authsvc stores pending state and redirects to `/login?saml_authn_id=…`.
3. User signs in; authsvc returns auto-submit HTML POSTing a signed `SAMLResponse` to the SP ACS.

## Production deployment

1. Register ACS URL `{ISSUER}/saml/acs` and SLO URL `{ISSUER}/saml/slo` with your IdP (SP mode).
2. Publish SP metadata from `GET /saml/metadata` (SP mode) or IdP metadata from `GET /saml/idp/metadata` (IdP mode).
3. Set `idp_cert_pem` and `require_signature: true` (SP mode).
4. For encrypted assertions, provide `sp_private_key_pem` matching the certificate registered with the IdP.
5. Monitor `docs/runbooks/` for incident response.

## Testing

```bash
cargo test -p authsvc-idp
cargo test -p authsvc-server --test saml_integration_test
cargo test -p authsvc-server --test integration_test saml_idp
```

Unit tests cover AuthnRequest generation, deflate encoding, and signature verification against signed fixtures.
