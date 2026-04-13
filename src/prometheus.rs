use std::collections::BTreeSet;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

use crate::processor::RateSnapshot;

pub type SharedSnapshots = Arc<RwLock<Vec<RateSnapshot>>>;

pub fn new_shared_snapshots() -> SharedSnapshots {
    Arc::new(RwLock::new(Vec::new()))
}

const METRICS: &[(&str, &str, fn(&RateSnapshot) -> f64)] = &[
    ("netalert_bps", "Bits per second", |s| s.bps),
    ("netalert_pps", "Packets per second", |s| s.pps),
    ("netalert_fps", "Flows per second", |s| s.fps),
];

fn render_metrics(snapshots: &[RateSnapshot]) -> String {
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

    out
}

/// Spawn the Prometheus metrics HTTP server in a background thread.
pub fn spawn(addr: String, snapshots: SharedSnapshots) {
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
                render_metrics(&snaps)
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
