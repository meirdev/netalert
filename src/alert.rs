use std::path::PathBuf;
use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use serde::Serialize;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{Config, Direction, MetricThresholds, ProtocolCategory};
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

    /// Build alert instances from config. Resets all alert states.
    pub fn reload_config(&mut self, config: &Config) {
        self.alerts.clear();

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
    pub async fn evaluate(&mut self, snapshots: &[RateSnapshot], processor: &mut FlowProcessor) {
        let now = Instant::now();

        // Collect payloads first to avoid borrow conflict
        let mut payloads = Vec::new();

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
                    let flows = processor.drain_captured_flows(&alert.prefix, alert.direction);
                    if flows.is_empty() {
                        Vec::new()
                    } else {
                        match alert.prefix.parse() {
                            Ok(prefix) => {
                                let rules = mitigation::analyze_flows(
                                    &flows,
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

        for payload in payloads {
            match serde_json::to_string(&payload) {
                Ok(json) => {
                    info!("Alert payload: {}", json);
                    self.execute_script(json).await;
                }
                Err(e) => error!("Failed to serialize alert payload: {}", e),
            }
        }
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
