use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use fxhash::FxHashMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::IntoStaticStr,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::IntoStaticStr,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolCategory {
    Tcp,
    Udp,
    Icmp,
    Gre,
    Esp,
    TcpSyn,
    Dns,
    Https,
    Any,
}

impl ProtocolCategory {
    pub fn classify(protocol: u8, tcp_flags: u8, dst_port: u16) -> Vec<ProtocolCategory> {
        let mut categories = vec![ProtocolCategory::Any];
        match protocol {
            6 => {
                categories.push(ProtocolCategory::Tcp);
                if tcp_flags & 0x02 != 0 {
                    categories.push(ProtocolCategory::TcpSyn);
                }
                if dst_port == 443 {
                    categories.push(ProtocolCategory::Https);
                }
                if dst_port == 53 {
                    categories.push(ProtocolCategory::Dns);
                }
            }
            17 => {
                categories.push(ProtocolCategory::Udp);
                if dst_port == 53 {
                    categories.push(ProtocolCategory::Dns);
                }
            }
            1 | 58 => categories.push(ProtocolCategory::Icmp),
            47 => categories.push(ProtocolCategory::Gre),
            50 => categories.push(ProtocolCategory::Esp),
            _ => {}
        }
        categories
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    #[serde(default)]
    pub exporters: FxHashMap<String, ExporterConfig>,
    #[serde(default)]
    pub alert_policies: FxHashMap<String, AlertPolicyConfig>,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(deserialize_with = "duration_str::deserialize_duration")]
    pub evaluation_interval: Duration,
    #[serde(deserialize_with = "duration_str::deserialize_duration")]
    pub window: Duration,
    pub alert_script: Option<String>,
    #[serde(default = "default_capture_buffer_size")]
    pub capture_buffer_size: usize,
    #[serde(
        default = "default_mitigation_update_interval",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    pub mitigation_update_interval: Duration,
}

fn default_capture_buffer_size() -> usize {
    500
}

fn default_mitigation_update_interval() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExporterConfig {
    pub address: IpAddr,
    pub sampling_rate: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertPolicyConfig {
    #[serde(deserialize_with = "duration_str::deserialize_duration")]
    pub trigger_for: Duration,
    #[serde(deserialize_with = "duration_str::deserialize_duration")]
    pub recover_for: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub prefix: IpNet,
    #[serde(default)]
    pub labels: FxHashMap<String, String>,
    pub alert_policy: Option<String>,
    pub thresholds: FxHashMap<ProtocolCategory, FxHashMap<Direction, DirectionMetrics>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectionMetrics {
    pub metrics: MetricThresholds,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MetricThresholds {
    pub bps: Option<ThresholdPair>,
    pub pps: Option<ThresholdPair>,
    pub fps: Option<ThresholdPair>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdPair {
    pub trigger: f64,
    #[serde(default)]
    pub recover: Option<f64>,
}

impl ThresholdPair {
    pub fn recover_value(&self) -> f64 {
        self.recover.unwrap_or(self.trigger)
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: Config =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse config YAML")?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        // Validate alert_policy references
        for (idx, rule) in self.rules.iter().enumerate() {
            if let Some(ref policy_name) = rule.alert_policy {
                if !self.alert_policies.contains_key(policy_name) {
                    anyhow::bail!(
                        "Rule {} (prefix {}) references unknown alert_policy '{}'",
                        idx,
                        rule.prefix,
                        policy_name
                    );
                }
            }

            // Validate at least one threshold per rule
            if rule.thresholds.is_empty() {
                anyhow::bail!(
                    "Rule {} (prefix {}) has no thresholds defined",
                    idx,
                    rule.prefix
                );
            }

            for (proto, directions) in &rule.thresholds {
                for (direction, dir_metrics) in directions {
                    let m = &dir_metrics.metrics;
                    if m.bps.is_none() && m.pps.is_none() && m.fps.is_none() {
                        anyhow::bail!(
                            "Rule {} (prefix {}): threshold {}/{} has no metrics defined",
                            idx,
                            rule.prefix,
                            proto,
                            direction
                        );
                    }
                }
            }
        }

        // Validate exporter addresses are unique
        let mut seen_addrs = std::collections::HashSet::new();
        for (name, exporter) in &self.exporters {
            if !seen_addrs.insert(exporter.address) {
                anyhow::bail!(
                    "Exporter '{}' has duplicate address {}",
                    name,
                    exporter.address
                );
            }
        }

        Ok(())
    }

    /// Build a lookup map from exporter IP address to sampling rate.
    pub fn exporter_sampling_rates(&self) -> FxHashMap<IpAddr, u32> {
        self.exporters
            .values()
            .map(|e| (e.address, e.sampling_rate))
            .collect()
    }
}
