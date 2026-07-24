# Production notifications (email & SMS)

This runbook covers configuring outbound email and SMS for magic links, OTP, and security alerts in production.

## Overview

| Channel | Provider | Config vars |
|---------|----------|-------------|
| Email | AWS SES (SMTP) | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` |
| SMS | Twilio | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` |

If no provider is configured, notifications are logged to stdout (development only). **Production deployments must configure at least one channel** for passwordless flows.

## Email (AWS SES)

### 1. Verify domain and sender

1. In AWS SES, verify your sending domain (or individual address).
2. Request production access if your account is still in the SES sandbox.
3. Create SMTP credentials under **SMTP settings**.

### 2. Configure authsvc

```bash
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=<ses-smtp-username>
SMTP_PASS=<ses-smtp-password>
SMTP_FROM=noreply@auth.example.com
```

### 3. Verify delivery

```bash
curl -X POST "$ISSUER/v1/auth/email-otp/send" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

Check SES sending statistics and CloudWatch for bounces/complaints.

### 4. Operational notes

- Set up SNS bounce/complaint notifications; suppress hard-bounced addresses.
- Use a dedicated subdomain (`auth.example.com`) for transactional mail.
- Rotate SMTP credentials via Secrets Manager; update Helm `secret` values and roll pods.

## SMS (Twilio)

### 1. Twilio setup

1. Create a Twilio account and purchase a phone number (or configure a Messaging Service).
2. Note **Account SID**, **Auth Token**, and the **From** number.

### 2. Configure authsvc

```bash
TWILIO_ACCOUNT_SID=ACxxxxxxxx
TWILIO_AUTH_TOKEN=xxxxxxxx
TWILIO_FROM_NUMBER=+15551234567
```

### 3. Verify delivery

```bash
curl -X POST "$ISSUER/v1/auth/phone-otp/send" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+15551234567"}'
```

### 4. Operational notes

- Enable Twilio fraud/geo permissions appropriate to your user base.
- Monitor Twilio Debugger and set alerts on error-rate spikes.
- Store credentials in Kubernetes secrets or your secrets manager; never commit to git.

## Helm / Kubernetes

Add to `deploy/helm/authsvc/values.yaml` under `env` (or use external secrets):

```yaml
env:
  SMTP_HOST: email-smtp.us-east-1.amazonaws.com
  SMTP_PORT: "587"
  SMTP_FROM: noreply@auth.example.com
  # TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER via secretRef
```

Reference sensitive values from `secret.yaml` and roll the deployment after changes.

## Failure modes

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| OTP never arrives (email) | SES sandbox, unverified sender | Verify domain/sender; exit sandbox |
| OTP never arrives (SMS) | Invalid From number or geo block | Check Twilio logs; verify number capabilities |
| `500` on send endpoints | Missing env in production | Set provider vars; check pod env |
| High latency | Provider rate limits | Back off client; request limit increase |

## Security

- Do not log OTP codes or magic-link tokens in application logs.
- Use TLS for SMTP (port 587 STARTTLS).
- Restrict Twilio Auth Token to the minimum required scopes.
- Review `RATE_LIMIT_PER_MINUTE` to limit OTP abuse.

## Related

- [deploy-production.md](../deploy-production.md) — full production checklist
- [account-lockdown.md](./account-lockdown.md) — incident response
