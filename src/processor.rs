use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use fxhash::FxHashMap;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use ipnet::IpNet;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::config::{Config, Direction, ProtocolCategory, RuleConfig};
use crate::flow::FlowRecord;
use crate::ring_buffer::RingBuffer;

/// A buffer key combining protocol category and direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BufferKey {
    pub protocol: ProtocolCategory,
    pub direction: Direction,
}

/// A captured flow with its classified direction for this rule.
#[derive(Debug, Clone)]
pub struct CapturedFlow {
    pub flow: FlowRecord,
    pub direction: Direction,
}

/// A processed rule from config, holding ring buffers for all
/// protocol × direction combinations that have thresholds defined.
pub struct ProcessedRule {
    pub prefix: IpNet,
    pub network: IpNetwork,
    pub labels: FxHashMap<String, String>,
    /// Ring buffers keyed by (protocol, direction)
    pub buffers: FxHashMap<BufferKey, RingBuffer>,
    /// Circular buffer of recent raw flows for flowspec analysis.
    pub capture_buffer: VecDeque<CapturedFlow>,
    pub capture_buffer_size: usize,
}

impl ProcessedRule {
    pub fn from_config(
        config: &RuleConfig,
        window_secs: usize,
        capture_buffer_size: usize,
    ) -> anyhow::Result<Self> {
        let network: IpNetwork = config
            .prefix
            .to_string()
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid prefix {}: {}", config.prefix, e))?;

        let mut buffers = FxHashMap::default();

        for (protocol, directions) in &config.thresholds {
            for (direction, _) in directions {
                let key = BufferKey {
                    protocol: *protocol,
                    direction: *direction,
                };
                buffers.insert(key, RingBuffer::new(window_secs));
            }
        }

        Ok(Self {
            prefix: config.prefix,
            network,
            labels: config.labels.clone(),
            buffers,
            capture_buffer: VecDeque::with_capacity(capture_buffer_size),
            capture_buffer_size,
        })
    }
}

pub struct FlowProcessor {
    pub rules: Vec<ProcessedRule>,
    /// Maps IP networks to indices in `rules` vec.
    /// Multiple rules can match the same IP (overlapping prefixes).
    prefix_table: IpNetworkTable<Vec<usize>>,
    window_secs: usize,
}

impl FlowProcessor {
    pub fn new(window_secs: usize) -> Self {
        Self {
            rules: Vec::new(),
            prefix_table: IpNetworkTable::new(),
            window_secs,
        }
    }

    pub fn reload_config(&mut self, config: &Config) -> anyhow::Result<()> {
        let window_secs = config.global.window.as_secs() as usize;
        let window = if window_secs > 0 {
            window_secs
        } else {
            self.window_secs
        };

        let mut new_rules = Vec::with_capacity(config.rules.len());
        let mut new_table: IpNetworkTable<Vec<usize>> = IpNetworkTable::new();

        let capture_buffer_size = config.global.capture_buffer_size;

        for (idx, rule_config) in config.rules.iter().enumerate() {
            let processed = ProcessedRule::from_config(rule_config, window, capture_buffer_size)?;

            // Add to prefix table - collect all rule indices per network
            if let Some(existing) = new_table.exact_match_mut(processed.network) {
                existing.push(idx);
            } else {
                new_table.insert(processed.network, vec![idx]);
            }

            new_rules.push(processed);
        }

        self.rules = new_rules;
        self.prefix_table = new_table;
        self.window_secs = window;
        Ok(())
    }

    /// Find all rule indices that match a given IP address.
    fn matching_rules(&self, ip: IpAddr) -> Vec<usize> {
        self.prefix_table
            .matches(ip)
            .flat_map(|(_, indices)| indices.iter().copied())
            .collect()
    }

    pub fn process_flow(&mut self, flow: &FlowRecord) {
        let bytes = flow.sampled_bytes();
        let packets = flow.sampled_packets();
        let protocol_cats =
            ProtocolCategory::classify(flow.protocol, flow.tcp_flags, flow.dst_port);

        // Find all rules where src or dst matches
        let src_rules = self.matching_rules(flow.src_ip);
        let dst_rules = self.matching_rules(flow.dst_ip);

        // Collect unique (rule_idx, direction) pairs
        let mut updates: Vec<(usize, Direction)> = Vec::new();

        // Rules matching dst only → Inbound (both in same prefix → skip)
        for &idx in &dst_rules {
            if !src_rules.contains(&idx) {
                updates.push((idx, Direction::Inbound));
            }
        }

        // Rules matching only src → Outbound
        for &idx in &src_rules {
            if !dst_rules.contains(&idx) {
                updates.push((idx, Direction::Outbound));
            }
        }

        // Distribute into ring buffers and capture flows
        for (rule_idx, direction) in updates {
            let rule = &mut self.rules[rule_idx];

            // Skip entirely if this direction has no threshold buffers defined
            if !rule.buffers.keys().any(|k| k.direction == direction) {
                continue;
            }

            // Push to capture buffer for flowspec analysis
            if rule.capture_buffer.len() >= rule.capture_buffer_size {
                rule.capture_buffer.pop_front();
            }
            rule.capture_buffer.push_back(CapturedFlow {
                flow: flow.clone(),
                direction,
            });

            for &protocol in &protocol_cats {
                let key = BufferKey {
                    protocol,
                    direction,
                };
                if let Some(buffer) = rule.buffers.get_mut(&key) {
                    buffer.add_instant_flow(flow.time_received, bytes, packets);
                }
            }
        }
    }

    /// Drain captured flows for all rules matching the given prefix and
    /// direction. Returns the flows and clears them from the capture buffers.
    pub fn drain_captured_flows(&mut self, prefix: &str, direction: Direction) -> Vec<FlowRecord> {
        let mut flows = Vec::new();
        for rule in &mut self.rules {
            if rule.prefix.to_string() == prefix {
                flows.extend(
                    rule.capture_buffer
                        .iter()
                        .filter(|cf| cf.direction == direction)
                        .map(|cf| cf.flow.clone()),
                );
                rule.capture_buffer.retain(|cf| cf.direction != direction);
            }
        }
        flows
    }

    pub fn compute_all_rates(&self, current_time: u64) -> Vec<RateSnapshot> {
        let mut snapshots = Vec::new();

        for rule in &self.rules {
            let prefix_str = rule.prefix.to_string();

            for (key, buffer) in &rule.buffers {
                let (bps, pps, fps) = buffer.compute_rates(current_time);
                snapshots.push(RateSnapshot {
                    prefix: prefix_str.clone(),
                    labels: rule.labels.clone(),
                    protocol: key.protocol,
                    direction: key.direction,
                    bps,
                    pps,
                    fps,
                });
            }
        }

        snapshots
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateSnapshot {
    pub prefix: String,
    pub labels: FxHashMap<String, String>,
    pub protocol: ProtocolCategory,
    pub direction: Direction,
    pub bps: f64,
    pub pps: f64,
    pub fps: f64,
}

pub type SharedProcessor = Arc<RwLock<FlowProcessor>>;

pub fn new_shared_processor(window_secs: usize) -> SharedProcessor {
    Arc::new(RwLock::new(FlowProcessor::new(window_secs)))
}
