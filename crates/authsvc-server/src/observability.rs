use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::TracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing(otel_endpoint: Option<&str>) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "authsvc_server=debug,tower_http=debug".into());

    if let Some(endpoint) = otel_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let provider = TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .build();
        let tracer = provider.tracer("authsvc");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    Ok(())
}

pub fn init_metrics() -> metrics_exporter_prometheus::PrometheusHandle {
    metrics::describe_counter!(
        "authsvc_login_total",
        "Total login attempts (success or failure)"
    );
    metrics::describe_counter!("authsvc_tokens_issued_total", "Access tokens issued");
    metrics::describe_counter!("authsvc_authz_checks_total", "Authorization checks");
    metrics::describe_counter!("authsvc_rate_limit_hits_total", "Rate limit rejections");
    metrics::describe_histogram!(
        "authsvc_http_request_duration_seconds",
        "HTTP request duration in seconds"
    );
    metrics::describe_counter!(
        "authsvc_jwt_key_age_alerts_total",
        "JWT signing key age exceeded policy threshold"
    );
    metrics::describe_counter!(
        "authsvc_archival_runs_total",
        "Archival background job runs"
    );

    PrometheusBuilder::new()
        .install_recorder()
        .expect("prometheus recorder")
}

pub fn record_login(success: bool) {
    metrics::counter!(
        "authsvc_login_total",
        "result" => if success { "success" } else { "failure" }
    )
    .increment(1);
}

pub fn record_token_issued() {
    metrics::counter!("authsvc_tokens_issued_total").increment(1);
}

pub fn record_authz_check() {
    metrics::counter!("authsvc_authz_checks_total").increment(1);
}

pub fn record_rate_limit_hit() {
    metrics::counter!("authsvc_rate_limit_hits_total").increment(1);
}

pub fn record_http_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    metrics::histogram!(
        "authsvc_http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path.to_string(),
        "status" => status.to_string()
    )
    .record(duration_secs);
}

pub fn record_jwt_key_age_alert() {
    metrics::counter!("authsvc_jwt_key_age_alerts_total").increment(1);
}

pub fn record_archival_run(success: bool) {
    metrics::counter!(
        "authsvc_archival_runs_total",
        "result" => if success { "success" } else { "failure" }
    )
    .increment(1);
}
