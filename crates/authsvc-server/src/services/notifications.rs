use async_trait::async_trait;
use authsvc_core::{AuthError, NotificationSender};

pub struct LogNotificationSender;

#[async_trait]
impl NotificationSender for LogNotificationSender {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError> {
        tracing::info!(to = %to, subject = %subject, body = %body, "notification (log)");
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
        // HTTP relay style SMTP gateway (e.g. Mailgun/SendGrid HTTP API) via SMTP_URL
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
}

pub fn build_notifier() -> Box<dyn NotificationSender> {
    if let Some(smtp) = SmtpNotificationSender::from_env() {
        Box::new(smtp)
    } else {
        Box::new(LogNotificationSender)
    }
}
