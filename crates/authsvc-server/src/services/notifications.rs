use async_trait::async_trait;
use authsvc_core::{AuthError, NotificationSender};

pub struct LogNotificationSender;

#[async_trait]
impl NotificationSender for LogNotificationSender {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        tracing::info!(to = %to, subject = %subject, body = %body, "notification (log)");
        Ok(())
    }

    async fn send_sms(&self, to: &str, body: &str) -> Result<(), AuthError> {
        tracing::info!(to = %to, body = %body, "sms (log)");
        Ok(())
    }
}

pub struct SmtpNotificationSender {
    smtp_url: String,
    from: String,
    client: reqwest::Client,
}

impl SmtpNotificationSender {
    pub fn from_env() -> Option<Self> {
        let smtp_url = std::env::var("SMTP_URL").ok()?;
        let from = std::env::var("SMTP_FROM").unwrap_or_else(|_| "authsvc@localhost".into());
        Some(Self {
            smtp_url,
            from,
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait]
impl NotificationSender for SmtpNotificationSender {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        let payload = serde_json::json!({
            "from": self.from,
            "to": to,
            "subject": subject,
            "text": body
        });
        self.client
            .post(&self.smtp_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn send_sms(&self, to: &str, body: &str) -> Result<(), AuthError> {
        tracing::info!(to = %to, body = %body, "sms (log fallback)");
        let _ = (to, body);
        Ok(())
    }
}

pub struct TwilioNotificationSender {
    account_sid: String,
    auth_token: String,
    from_number: String,
    client: reqwest::Client,
    email_fallback: Option<SmtpNotificationSender>,
}

impl TwilioNotificationSender {
    pub fn from_env() -> Option<Self> {
        let account_sid = std::env::var("TWILIO_ACCOUNT_SID").ok()?;
        let auth_token = std::env::var("TWILIO_AUTH_TOKEN").ok()?;
        let from_number = std::env::var("TWILIO_FROM_NUMBER").ok()?;
        Some(Self {
            account_sid,
            auth_token,
            from_number,
            client: reqwest::Client::new(),
            email_fallback: SmtpNotificationSender::from_env(),
        })
    }
}

#[async_trait]
impl NotificationSender for TwilioNotificationSender {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        if let Some(smtp) = &self.email_fallback {
            smtp.send_email(to, subject, body).await
        } else {
            LogNotificationSender.send_email(to, subject, body).await
        }
    }

    async fn send_sms(&self, to: &str, body: &str) -> Result<(), AuthError> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );
        self.client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&[
                ("To", to),
                ("From", self.from_number.as_str()),
                ("Body", body),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

pub fn build_notifier() -> Box<dyn NotificationSender> {
    if let Some(twilio) = TwilioNotificationSender::from_env() {
        return Box::new(twilio);
    }
    if let Some(smtp) = SmtpNotificationSender::from_env() {
        return Box::new(smtp);
    }
    Box::new(LogNotificationSender)
}
