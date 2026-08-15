use std::collections::BTreeSet;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::alert::AlertStateSnapshot;
use crate::processor::RateSnapshot;

pub type SharedSnapshots = Arc<RwLock<Vec<RateSnapshot>>>;
pub type SharedAlertStates = Arc<RwLock<Vec<AlertStateSnapshot>>>;

pub fn new_shared_snapshots() -> SharedSnapshots {
    Arc::new(RwLock::new(Vec::new()))
}

pub fn new_shared_alert_states() -> SharedAlertStates {
    Arc::new(RwLock::new(Vec::new()))
}

/// Internal daemon health counters, updated from the hot paths with relaxed
/// atomics and rendered by the metrics endpoint.
#[derive(Debug, Default)]
pub struct HealthMetrics {
    pub flows_received_netflow: AtomicU64,
    pub flows_received_sflow: AtomicU64,
    /// Flows dropped because the processing channel was full.
    pub flows_dropped: AtomicU64,
    /// Current depth of the flow processing channel.
    pub flow_channel_depth: AtomicU64,
    /// Duration of the last threshold evaluation pass, in microseconds.
    pub evaluation_duration_micros: AtomicU64,
}

pub type SharedHealth = Arc<HealthMetrics>;

pub fn new_shared_health() -> SharedHealth {
    Arc::new(HealthMetrics::default())
}

const METRICS: &[(&str, &str, fn(&RateSnapshot) -> f64)] = &[
    ("netalert_bps", "Bits per second", |s| s.bps),
    ("netalert_pps", "Packets per second", |s| s.pps),
    ("netalert_fps", "Flows per second", |s| s.fps),
];

fn render_alert_states(out: &mut String, states: &[AlertStateSnapshot]) {
    writeln!(
        out,
        "# HELP netalert_alert_state Alert state machine position (0=normal, 1=pending, 2=firing, 3=recovering)"
    )
    .unwrap();
    writeln!(out, "# TYPE netalert_alert_state gauge").unwrap();

    for s in states {
        writeln!(
            out,
            "netalert_alert_state{{prefix=\"{}\",protocol=\"{}\",direction=\"{}\",metric=\"{}\"}} {}",
            s.prefix, s.protocol, s.direction, s.metric, s.state
        )
        .unwrap();
    }
}

fn render_health(out: &mut String, health: &HealthMetrics) {
    writeln!(
        out,
        "# HELP netalert_flows_received_total Flows received per collector"
    )
    .unwrap();
    writeln!(out, "# TYPE netalert_flows_received_total counter").unwrap();
    let received = [
        ("netflow", &health.flows_received_netflow),
        ("sflow", &health.flows_received_sflow),
    ];
    for (source, counter) in received {
        writeln!(
            out,
            "netalert_flows_received_total{{source=\"{}\"}} {}",
            source,
            counter.load(Ordering::Relaxed)
        )
        .unwrap();
    }

    writeln!(
        out,
        "# HELP netalert_flows_dropped_total Flows dropped because the processing channel was full"
    )
    .unwrap();
    writeln!(out, "# TYPE netalert_flows_dropped_total counter").unwrap();
    writeln!(
        out,
        "netalert_flows_dropped_total {}",
        health.flows_dropped.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP netalert_flow_channel_depth Flows currently queued for processing"
    )
    .unwrap();
    writeln!(out, "# TYPE netalert_flow_channel_depth gauge").unwrap();
    writeln!(
        out,
        "netalert_flow_channel_depth {}",
        health.flow_channel_depth.load(Ordering::Relaxed)
    )
    .unwrap();

    writeln!(
        out,
        "# HELP netalert_evaluation_duration_seconds Duration of the last threshold evaluation pass"
    )
    .unwrap();
    writeln!(out, "# TYPE netalert_evaluation_duration_seconds gauge").unwrap();
    writeln!(
        out,
        "netalert_evaluation_duration_seconds {}",
        health.evaluation_duration_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    )
    .unwrap();
}

fn render_metrics(
    snapshots: &[RateSnapshot],
    alert_states: &[AlertStateSnapshot],
    health: &HealthMetrics,
) -> String {
    let extra_keys: Vec<String> = snapshots
        .iter()
        .flat_map(|s| s.labels.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut out = String::new();

    for (name, help, get_val) in METRICS {
        writeln!(out, "# HELP {name} {help}").unwrap();
        writeln!(out, "# TYPE {name} gauge").unwrap();

        for s in snapshots {
            write!(
                out,
                "{name}{{prefix=\"{}\",protocol=\"{}\",direction=\"{}\"",
                s.prefix, s.protocol, s.direction
            )
            .unwrap();

            for key in &extra_keys {
                let val = s.labels.get(key).map(|s| s.as_str()).unwrap_or("");
                write!(out, ",{key}=\"{val}\"").unwrap();
            }

            writeln!(out, "}} {}", get_val(s)).unwrap();
        }
    }

    render_alert_states(&mut out, alert_states);
    render_health(&mut out, health);

    out
}

/// Spawn the Prometheus metrics HTTP server in a background thread.
pub fn spawn(
    addr: String,
    snapshots: SharedSnapshots,
    alert_states: SharedAlertStates,
    health: SharedHealth,
) {
    std::thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to bind Prometheus endpoint {}: {}", addr, e);
                return;
            }
        };

        tracing::info!(
            "Prometheus metrics endpoint listening on http://{}/metrics",
            addr
        );

        for request in server.incoming_requests() {
            let body = if request.url() == "/metrics" {
                let snaps = snapshots.read().unwrap();
                let states = alert_states.read().unwrap();
                render_metrics(&snaps, &states, &health)
            } else {
                "# metrics available at /metrics\n".to_string()
            };

            let response = tiny_http::Response::from_string(body).with_header(
                tiny_http::Header::from_bytes(
                    b"Content-Type",
                    b"text/plain; version=0.0.4; charset=utf-8",
                )
                .unwrap(),
            );

            let _ = request.respond(response);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::MetricType;
    use crate::config::{Direction, ProtocolCategory};

    #[test]
    fn renders_health_and_alert_state() {
        let health = HealthMetrics::default();
        health.flows_received_netflow.store(10, Ordering::Relaxed);
        health.flows_dropped.store(2, Ordering::Relaxed);
        health.flow_channel_depth.store(7, Ordering::Relaxed);
        health
            .evaluation_duration_micros
            .store(1500, Ordering::Relaxed);

        let states = vec![AlertStateSnapshot {
            prefix: "10.0.0.0/24".to_string(),
            protocol: ProtocolCategory::Any,
            direction: Direction::Inbound,
            metric: MetricType::Bps,
            state: 2,
        }];

        let out = render_metrics(&[], &states, &health);

        assert!(out.contains("netalert_flows_received_total{source=\"netflow\"} 10"));
        assert!(out.contains("netalert_flows_received_total{source=\"sflow\"} 0"));
        assert!(out.contains("netalert_flows_dropped_total 2"));
        assert!(out.contains("netalert_flow_channel_depth 7"));
        assert!(out.contains("netalert_evaluation_duration_seconds 0.0015"));
        assert!(out.contains(
            "netalert_alert_state{prefix=\"10.0.0.0/24\",protocol=\"any\",direction=\"inbound\",metric=\"bps\"} 2"
        ));
    }
}
