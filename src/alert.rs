use std::path::PathBuf;
use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use serde::Serialize;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{Config, Direction, MetricThresholds, ProtocolCategory};
use crate::flow::FlowRecord;
use crate::mitigation::{self, MitigationRule};
use crate::processor::{FlowProcessor, RateSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    /// Rate is below trigger threshold.
    Normal,
    /// Rate exceeded trigger threshold, waiting for trigger_for duration.
    Pending { since: Instant },
    /// Alert has fired (script was called with "trigger").
    Firing { last_update: Instant },
    /// Rate dropped below recover threshold, waiting for recover_for duration.
    Recovering { since: Instant },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, strum::Display, strum::IntoStaticStr,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum MetricType {
    Bps,
    Pps,
    Fps,
}

/// One alert instance per (rule, protocol, direction, metric) combination.
pub struct AlertInstance {
    pub state: AlertState,
    pub alert_id: Uuid,
    pub prefix: String,
    pub protocol: ProtocolCategory,
    pub direction: Direction,
    pub metric: MetricType,
    pub trigger_threshold: f64,
    pub recover_threshold: f64,
    pub trigger_for: Duration,
    pub recover_for: Duration,
    pub mitigation_update_interval: Duration,
    pub labels: FxHashMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub enum AlertAction {
    Fire,
    /// Periodic re-analysis while alert is still firing.
    Update,
    Resolve,
}

/// JSON payload sent to the alert script via stdin.
#[derive(Debug, Serialize)]
pub struct AlertPayload {
    pub alert_id: Uuid,
    pub action: String,
    pub prefix: String,
    pub protocol: String,
    pub direction: String,
    pub metric: String,
    pub value: f64,
    pub threshold: f64,
    pub labels: FxHashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitigation_rules: Vec<MitigationRule>,
}

impl AlertInstance {
    /// Evaluate the current rate and advance the state machine.
    /// Returns an action if a script should be called.
    pub fn evaluate(&mut self, current_rate: f64, now: Instant) -> Option<AlertAction> {
        match self.state {
            AlertState::Normal => {
                if current_rate >= self.trigger_threshold {
                    self.state = AlertState::Pending { since: now };
                }
                None
            }
            AlertState::Pending { since } => {
                if current_rate < self.trigger_threshold {
                    // Rate dropped back below threshold before trigger_for elapsed
                    self.state = AlertState::Normal;
                    None
                } else if now.duration_since(since) >= self.trigger_for {
                    self.state = AlertState::Firing { last_update: now };
                    Some(AlertAction::Fire)
                } else {
                    None
                }
            }
            AlertState::Firing { last_update } => {
                if current_rate < self.recover_threshold {
                    self.state = AlertState::Recovering { since: now };
                    None
                } else if now.duration_since(last_update) >= self.mitigation_update_interval {
                    // Periodically re-analyze while still firing
                    self.state = AlertState::Firing { last_update: now };
                    Some(AlertAction::Update)
                } else {
                    None
                }
            }
            AlertState::Recovering { since } => {
                if current_rate >= self.recover_threshold {
                    // Rate climbed back up, reset recovery
                    self.state = AlertState::Firing { last_update: now };
                    None
                } else if now.duration_since(since) >= self.recover_for {
                    self.state = AlertState::Normal;
                    Some(AlertAction::Resolve)
                } else {
                    None
                }
            }
        }
    }

    fn build_payload(
        &self,
        value: f64,
        action: &str,
        mitigation_rules: Vec<MitigationRule>,
    ) -> AlertPayload {
        AlertPayload {
            alert_id: self.alert_id,
            action: action.to_string(),
            prefix: self.prefix.clone(),
            protocol: self.protocol.to_string(),
            direction: self.direction.to_string(),
            metric: self.metric.to_string(),
            value,
            threshold: if action == "trigger" || action == "update" {
                self.trigger_threshold
            } else {
                self.recover_threshold
            },
            labels: self.labels.clone(),
            mitigation_rules,
        }
    }
}

/// Snapshot of an alert instance's state for the metrics endpoint.
#[derive(Debug, Clone)]
pub struct AlertStateSnapshot {
    pub prefix: String,
    pub protocol: ProtocolCategory,
    pub direction: Direction,
    pub metric: MetricType,
    /// 0=normal, 1=pending, 2=firing, 3=recovering
    pub state: u8,
}

pub struct AlertManager {
    pub alerts: Vec<AlertInstance>,
    pub script_path: Option<PathBuf>,
}

impl AlertManager {
    pub fn new(script_path: Option<PathBuf>) -> Self {
        Self {
            alerts: Vec::new(),
            script_path,
        }
    }

    /// Build alert instances from config. State is carried over by
    /// (prefix, protocol, direction, metric) so a reload does not orphan a
    /// firing alert — resetting it to Normal would mean its resolve is never
    /// sent and any mitigation installed by the script stays up forever.
    pub fn reload_config(&mut self, config: &Config) {
        let mut previous: FxHashMap<
            (String, ProtocolCategory, Direction, MetricType),
            (AlertState, Uuid),
        > = self
            .alerts
            .drain(..)
            .map(|a| {
                (
                    (a.prefix, a.protocol, a.direction, a.metric),
                    (a.state, a.alert_id),
                )
            })
            .collect();

        // Default policy if none specified
        let default_trigger_for = Duration::from_secs(10);
        let default_recover_for = Duration::from_secs(20);

        if let Some(ref script) = config.global.alert_script {
            self.script_path = Some(PathBuf::from(script));
        }

        let mitigation_update_interval = config.global.mitigation_update_interval;

        for rule in &config.rules {
            let (trigger_for, recover_for) = if let Some(ref policy_name) = rule.alert_policy {
                if let Some(policy) = config.alert_policies.get(policy_name) {
                    (policy.trigger_for, policy.recover_for)
                } else {
                    (default_trigger_for, default_recover_for)
                }
            } else {
                (default_trigger_for, default_recover_for)
            };

            let prefix_str = rule.prefix.to_string();

            for (protocol, directions) in &rule.thresholds {
                for (direction, dir_metrics) in directions {
                    let m = &dir_metrics.metrics;
                    self.add_metric_alerts(
                        &prefix_str,
                        *protocol,
                        *direction,
                        m,
                        trigger_for,
                        recover_for,
                        mitigation_update_interval,
                        &rule.labels,
                    );
                }
            }
        }

        for alert in &mut self.alerts {
            let key = (
                alert.prefix.clone(),
                alert.protocol,
                alert.direction,
                alert.metric,
            );
            if let Some((state, alert_id)) = previous.remove(&key) {
                alert.state = state;
                alert.alert_id = alert_id;
            }
        }

        for ((prefix, protocol, direction, metric), (state, _)) in previous {
            if !matches!(state, AlertState::Normal) {
                warn!(
                    "Alert {}/{}/{}/{} was removed by config reload while active; no resolve will be sent",
                    prefix, protocol, direction, metric
                );
            }
        }

        info!(
            "Alert manager: {} alert instances configured",
            self.alerts.len()
        );
    }

    fn add_metric_alerts(
        &mut self,
        prefix: &str,
        protocol: ProtocolCategory,
        direction: Direction,
        thresholds: &MetricThresholds,
        trigger_for: Duration,
        recover_for: Duration,
        mitigation_update_interval: Duration,
        labels: &FxHashMap<String, String>,
    ) {
        let pairs: [(MetricType, &Option<crate::config::ThresholdPair>); 3] = [
            (MetricType::Bps, &thresholds.bps),
            (MetricType::Pps, &thresholds.pps),
            (MetricType::Fps, &thresholds.fps),
        ];

        for (metric_type, threshold_opt) in pairs {
            if let Some(threshold) = threshold_opt {
                self.alerts.push(AlertInstance {
                    state: AlertState::Normal,
                    alert_id: Uuid::nil(),
                    prefix: prefix.to_string(),
                    protocol,
                    direction,
                    metric: metric_type,
                    trigger_threshold: threshold.trigger,
                    recover_threshold: threshold.recover_value(),
                    trigger_for,
                    recover_for,
                    mitigation_update_interval,
                    labels: labels.clone(),
                });
            }
        }
    }

    /// Evaluate all alerts against current rate snapshots.
    /// When an alert fires, drains captured flows from the processor to
    /// generate BGP Flow Spec rule suggestions.
    pub async fn evaluate(
        &mut self,
        snapshots: &[RateSnapshot],
        processor: &mut FlowProcessor,
    ) -> Vec<AlertPayload> {
        let now = Instant::now();

        // Collect payloads first to avoid borrow conflict
        let mut payloads = Vec::new();

        // Capture buffers are drained once per (prefix, direction) this tick
        // and shared by every alert on that key — draining per alert would
        // hand all captured flows to whichever alert fires first and leave
        // the others with nothing to analyze.
        let mut drained: FxHashMap<(String, Direction), Vec<FlowRecord>> = FxHashMap::default();

        for alert in &mut self.alerts {
            let current_rate = find_rate(
                snapshots,
                &alert.prefix,
                alert.protocol,
                alert.direction,
                alert.metric,
            );

            if let Some(action) = alert.evaluate(current_rate, now) {
                if matches!(action, AlertAction::Fire) {
                    alert.alert_id = Uuid::new_v4();
                }

                let action_str = match action {
                    AlertAction::Fire => "trigger",
                    AlertAction::Update => "update",
                    AlertAction::Resolve => "resolve",
                };

                let threshold = match action {
                    AlertAction::Fire | AlertAction::Update => alert.trigger_threshold,
                    AlertAction::Resolve => alert.recover_threshold,
                };

                info!(
                    "Alert {}: {} {}/{}/{} value={:.2} threshold={:.2}",
                    action_str,
                    alert.prefix,
                    alert.protocol,
                    alert.direction,
                    alert.metric,
                    current_rate,
                    threshold
                );

                // On fire or update: analyze captured flows for mitigation suggestions
                let mitigation_rules = if matches!(action, AlertAction::Fire | AlertAction::Update)
                {
                    let flows = drained
                        .entry((alert.prefix.clone(), alert.direction))
                        .or_insert_with(|| {
                            processor.drain_captured_flows(&alert.prefix, alert.direction)
                        });
                    if flows.is_empty() {
                        Vec::new()
                    } else {
                        match alert.prefix.parse() {
                            Ok(prefix) => {
                                let rules = mitigation::analyze_flows(
                                    flows,
                                    prefix,
                                    alert.direction,
                                    alert.protocol,
                                    current_rate,
                                    alert.trigger_threshold,
                                );
                                if !rules.is_empty() {
                                    info!(
                                        "Generated {} mitigation rule(s) for {} {}",
                                        rules.len(),
                                        alert.prefix,
                                        alert.direction
                                    );
                                }
                                rules
                            }
                            Err(e) => {
                                error!(
                                    "Failed to parse prefix '{}' for mitigation analysis: {}",
                                    alert.prefix, e
                                );
                                Vec::new()
                            }
                        }
                    }
                } else {
                    Vec::new()
                };

                payloads.push(alert.build_payload(current_rate, action_str, mitigation_rules));
            }
        }

        for payload in &payloads {
            match serde_json::to_string(payload) {
                Ok(json) => {
                    info!("Alert payload: {}", json);
                    self.execute_script(json).await;
                }
                Err(e) => error!("Failed to serialize alert payload: {}", e),
            }
        }

        payloads
    }

    /// Current state of every alert instance, for the metrics endpoint.
    pub fn state_snapshots(&self) -> Vec<AlertStateSnapshot> {
        self.alerts
            .iter()
            .map(|a| AlertStateSnapshot {
                prefix: a.prefix.clone(),
                protocol: a.protocol,
                direction: a.direction,
                metric: a.metric,
                state: match a.state {
                    AlertState::Normal => 0,
                    AlertState::Pending { .. } => 1,
                    AlertState::Firing { .. } => 2,
                    AlertState::Recovering { .. } => 3,
                },
            })
            .collect()
    }

    async fn execute_script(&self, json: String) {
        let script_path = match &self.script_path {
            Some(p) => p.clone(),
            None => {
                warn!("Alert triggered but no alert_script configured");
                return;
            }
        };

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            use tokio::process::Command;

            let mut child = match Command::new(&script_path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to spawn alert script {:?}: {}", script_path, e);
                    return;
                }
            };

            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(json.as_bytes()).await {
                    error!("Failed to write to alert script stdin: {}", e);
                    return;
                }
            }

            match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
                Ok(Ok(status)) => {
                    if !status.success() {
                        warn!("Alert script exited with status: {}", status);
                    }
                }
                Ok(Err(e)) => {
                    error!("Alert script wait error: {}", e);
                }
                Err(_) => {
                    warn!("Alert script timed out after 30s");
                    let _ = child.kill().await;
                }
            }
        });
    }
}

/// Find the rate value for a specific alert from the snapshots.
fn find_rate(
    snapshots: &[RateSnapshot],
    prefix: &str,
    protocol: ProtocolCategory,
    direction: Direction,
    metric: MetricType,
) -> f64 {
    for s in snapshots {
        if s.prefix == prefix && s.protocol == protocol && s.direction == direction {
            return match metric {
                MetricType::Bps => s.bps,
                MetricType::Pps => s.pps,
                MetricType::Fps => s.fps,
            };
        }
    }
    0.0
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::processor::FlowProcessor;

    const CONFIG_YAML: &str = r#"
global:
  evaluation_interval: 1s
  window: 10s

alert_policies:
  instant:
    trigger_for: 0s
    recover_for: 0s

rules:
  - prefix: 10.0.0.0/24
    alert_policy: instant
    thresholds:
      any:
        inbound:
          metrics:
            bps:
              trigger: 100
            pps:
              trigger: 10
"#;

    fn test_config() -> Config {
        serde_yaml::from_str(CONFIG_YAML).unwrap()
    }

    fn snapshot(bps: f64, pps: f64) -> RateSnapshot {
        RateSnapshot {
            prefix: "10.0.0.0/24".to_string(),
            labels: FxHashMap::default(),
            protocol: ProtocolCategory::Any,
            direction: Direction::Inbound,
            bps,
            pps,
            fps: 0.0,
        }
    }

    #[test]
    fn reload_preserves_alert_state() {
        let config = test_config();
        let mut mgr = AlertManager::new(None);
        mgr.reload_config(&config);
        assert_eq!(mgr.alerts.len(), 2);

        let id = Uuid::new_v4();
        let idx = mgr
            .alerts
            .iter()
            .position(|a| a.metric == MetricType::Bps)
            .unwrap();
        mgr.alerts[idx].state = AlertState::Firing {
            last_update: Instant::now(),
        };
        mgr.alerts[idx].alert_id = id;

        mgr.reload_config(&config);

        let firing = mgr
            .alerts
            .iter()
            .find(|a| a.metric == MetricType::Bps)
            .unwrap();
        assert!(matches!(firing.state, AlertState::Firing { .. }));
        assert_eq!(firing.alert_id, id);

        let other = mgr
            .alerts
            .iter()
            .find(|a| a.metric == MetricType::Pps)
            .unwrap();
        assert!(matches!(other.state, AlertState::Normal));
    }

    #[tokio::test]
    async fn concurrent_alerts_share_captured_flows() {
        let config = test_config();
        let mut processor = FlowProcessor::new(10);
        processor.reload_config(&config).unwrap();

        // Capture a DNS-amplification-shaped batch of inbound flows.
        for i in 0..50u16 {
            let flow = FlowRecord {
                src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, i as u8)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                src_port: 53,
                dst_port: 30000 + i,
                protocol: 17,
                tcp_flags: 0,
                bytes: 4096,
                packets: 1,
                time_received: 1000,
                sampling_rate: 1,
            };
            processor.process_flow(&flow);
        }

        let mut mgr = AlertManager::new(None);
        mgr.reload_config(&config);

        let snapshots = vec![snapshot(1_000_000.0, 100_000.0)];

        // First pass arms both alerts (Normal → Pending)...
        let payloads = mgr.evaluate(&snapshots, &mut processor).await;
        assert!(payloads.is_empty());

        // ...second pass fires both (trigger_for is 0s). Both the bps and
        // pps alert must get mitigation rules from the shared capture
        // buffer, not just whichever drained it first.
        let payloads = mgr.evaluate(&snapshots, &mut processor).await;
        assert_eq!(payloads.len(), 2);
        for payload in &payloads {
            assert_eq!(payload.action, "trigger");
            assert!(
                !payload.mitigation_rules.is_empty(),
                "alert {}/{} lost the captured flows",
                payload.metric,
                payload.prefix
            );
        }
    }
}
