use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;

use crate::config::{Direction, ProtocolCategory};
use crate::flow::FlowRecord;

/// A suggested BGP Flow Spec rule.
#[derive(Debug, Clone, Serialize)]
pub struct MitigationRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_prefix: Option<String>,
    pub destination_prefix: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub destination_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tcp_flags: Vec<String>,
}

/// Which fields a candidate rule constrains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FieldSet(u8);

impl FieldSet {
    const SRC_IP: u8 = 1 << 0;
    const DST_PORT: u8 = 1 << 1;
    const SRC_PORT: u8 = 1 << 2;
    const PROTOCOL: u8 = 1 << 3;
    const TCP_FLAGS: u8 = 1 << 4;

    fn count(self) -> u32 {
        self.0.count_ones()
    }

    fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Generate all non-empty subsets of fields, excluding any in
    /// `exclude_mask`.
    fn all_combinations(exclude_mask: u8) -> Vec<FieldSet> {
        let available = !exclude_mask & 0b11111;
        let mut result = Vec::new();
        // Generate all non-empty subsets of available fields
        for bits in 1u8..=0b11111 {
            // Only keep subsets that use only available fields
            if bits & !available != 0 {
                continue;
            }
            result.push(FieldSet(bits));
        }
        // Sort by field count ascending
        result.sort_by_key(|fs| fs.count());
        result
    }
}

/// A concrete candidate rule: specific field values + coverage.
#[derive(Debug, Clone)]
struct Candidate {
    fields: FieldSet,
    src_ip: Option<IpAddr>,
    dst_port: Option<u16>,
    src_port: Option<u16>,
    protocol: Option<u8>,
    tcp_flags: Option<u8>,
}

impl Candidate {
    fn matches(&self, flow: &FlowRecord) -> bool {
        if let Some(ip) = self.src_ip
            && flow.src_ip != ip
        {
            return false;
        }
        if let Some(port) = self.dst_port
            && flow.dst_port != port
        {
            return false;
        }
        if let Some(port) = self.src_port
            && flow.src_port != port
        {
            return false;
        }
        if let Some(proto) = self.protocol
            && flow.protocol != proto
        {
            return false;
        }
        if let Some(flags) = self.tcp_flags
            && flow.tcp_flags & flags != flags
        {
            return false;
        }
        true
    }
}

/// Key for grouping flows by a specific field combination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupKey {
    src_ip: Option<IpAddr>,
    dst_port: Option<u16>,
    src_port: Option<u16>,
    protocol: Option<u8>,
    tcp_flags: Option<u8>,
}

impl GroupKey {
    fn from_flow(flow: &FlowRecord, fields: FieldSet) -> Option<Self> {
        // Skip zero-value fields that aren't meaningful constraints.
        // tcp_flags=0, protocol=0, port=0 match almost everything and produce useless
        // rules.
        if fields.has(FieldSet::TCP_FLAGS) && flow.tcp_flags == 0 {
            return None;
        }
        if fields.has(FieldSet::PROTOCOL) && flow.protocol == 0 {
            return None;
        }
        if fields.has(FieldSet::DST_PORT) && flow.dst_port == 0 {
            return None;
        }
        if fields.has(FieldSet::SRC_PORT) && flow.src_port == 0 {
            return None;
        }

        Some(Self {
            src_ip: if fields.has(FieldSet::SRC_IP) {
                Some(flow.src_ip)
            } else {
                None
            },
            dst_port: if fields.has(FieldSet::DST_PORT) {
                Some(flow.dst_port)
            } else {
                None
            },
            src_port: if fields.has(FieldSet::SRC_PORT) {
                Some(flow.src_port)
            } else {
                None
            },
            protocol: if fields.has(FieldSet::PROTOCOL) {
                Some(flow.protocol)
            } else {
                None
            },
            tcp_flags: if fields.has(FieldSet::TCP_FLAGS) {
                Some(flow.tcp_flags)
            } else {
                None
            },
        })
    }
}

/// Compute the most specific destination prefix for a set of flows.
/// For inbound traffic, looks at dst_ip; for outbound, looks at src_ip.
/// If a single host accounts for >= `dominant_ratio` of total bytes, returns
/// that host as a /32 (or /128). Otherwise returns the full rule prefix.
fn compute_destination_prefix(
    flows: &[FlowRecord],
    direction: Direction,
    prefix: IpNet,
    dominant_ratio: f64,
) -> IpNet {
    let total_bytes: u64 = flows.iter().map(|f| f.sampled_bytes()).sum();
    if total_bytes == 0 {
        return prefix;
    }

    let mut counts: HashMap<IpAddr, u64> = HashMap::new();
    for flow in flows {
        let ip = match direction {
            Direction::Inbound => flow.dst_ip,
            Direction::Outbound => flow.src_ip,
        };
        *counts.entry(ip).or_insert(0) += flow.sampled_bytes();
    }

    if let Some((&ip, &bytes)) = counts.iter().max_by_key(|&(_, &v)| v)
        && bytes as f64 / total_bytes as f64 >= dominant_ratio
    {
        let host_prefix = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };
        if let Ok(parsed) = host_prefix.parse() {
            return parsed;
        }
    }

    prefix
}

fn proto_number(cat: ProtocolCategory) -> u8 {
    match cat {
        ProtocolCategory::Tcp | ProtocolCategory::TcpSyn | ProtocolCategory::Https => 6,
        ProtocolCategory::Udp => 17,
        ProtocolCategory::Icmp => 1,
        ProtocolCategory::Gre => 47,
        ProtocolCategory::Esp => 50,
        // DNS can be UDP or TCP — no single protocol number
        ProtocolCategory::Any | ProtocolCategory::Dns => 0,
    }
}

fn protocol_name(proto: u8) -> String {
    match proto {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        47 => "gre".to_string(),
        50 => "esp".to_string(),
        58 => "icmp6".to_string(),
        n => n.to_string(),
    }
}

fn tcp_flag_names(flags: u8) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("fin".to_string());
    }
    if flags & 0x02 != 0 {
        names.push("syn".to_string());
    }
    if flags & 0x04 != 0 {
        names.push("rst".to_string());
    }
    if flags & 0x08 != 0 {
        names.push("psh".to_string());
    }
    if flags & 0x10 != 0 {
        names.push("ack".to_string());
    }
    if flags & 0x20 != 0 {
        names.push("urg".to_string());
    }
    names
}

/// Find the best candidate rule from a set of flows.
/// Returns None if no candidate covers at least `min_coverage_ratio` of total
/// bytes. `exclude_fields` is a bitmask of fields to exclude from the search
/// (e.g. PROTOCOL when we already know the protocol from the alert).
fn find_best_candidate(
    flows: &[FlowRecord],
    min_coverage_ratio: f64,
    exclude_fields: u8,
) -> Option<Candidate> {
    if flows.is_empty() {
        return None;
    }

    let total_bytes: u64 = flows.iter().map(|f| f.sampled_bytes()).sum();
    if total_bytes == 0 {
        return None;
    }

    let field_sets = FieldSet::all_combinations(exclude_fields);
    let mut best: Option<(Candidate, f64)> = None;

    for fields in &field_sets {
        // Group flows by this field combination
        let mut groups: HashMap<GroupKey, (u64, u64)> = HashMap::new();

        for flow in flows {
            if let Some(key) = GroupKey::from_flow(flow, *fields) {
                let entry = groups.entry(key).or_insert((0, 0));
                entry.0 += flow.sampled_bytes();
                entry.1 += flow.sampled_packets();
            }
        }

        // Find the best group for this field set
        for (key, (bytes, _packets)) in &groups {
            let coverage = *bytes as f64 / total_bytes as f64;
            if coverage < min_coverage_ratio {
                continue;
            }

            let candidate = Candidate {
                fields: *fields,
                src_ip: key.src_ip,
                dst_port: key.dst_port,
                src_port: key.src_port,
                protocol: key.protocol,
                tcp_flags: key.tcp_flags,
            };

            // Score balances coverage and specificity:
            //   score = coverage_ratio * (1.0 + 0.1 * field_count)
            // More fields get a bonus, but can't overcome a large coverage drop.
            // Example: protocol=tcp at 100% scores 1.0*1.1=1.1
            //          {protocol=tcp, dst_port=7873} at 96.6% scores 0.966*1.2=1.16 ← wins
            //          {src_ip=X, protocol, dst_port} at 10% scores 0.1*1.3=0.13 ← too
            // narrow
            let score = coverage * (1.0 + 0.1 * candidate.fields.count() as f64);

            let dominated = match &best {
                None => true,
                Some((_, best_score)) => score > *best_score,
            };

            if dominated {
                best = Some((candidate, score));
            }
        }
    }

    best.map(|(c, _)| c)
}

/// Analyze captured flows and generate BGP Flow Spec rules.
///
/// Uses a multi-vector approach: iteratively finds the best pattern,
/// removes matched flows, and repeats until remaining traffic is below
/// the threshold or max rules are reached.
///
/// `current_rate` and `threshold` control when to stop: after each rule,
/// we estimate the remaining rate as `current_rate * (remaining_bytes /
/// total_bytes)`. When that drops below `threshold`, we stop — avoiding rules
/// for legitimate traffic.
///
/// When `protocol_filter` is a specific protocol (not `Any`), flows are
/// pre-filtered to only that protocol and the protocol is always included
/// in generated rules.
pub fn analyze_flows(
    flows: &[FlowRecord],
    dest_prefix: IpNet,
    direction: Direction,
    protocol_filter: ProtocolCategory,
    current_rate: f64,
    threshold: f64,
) -> Vec<MitigationRule> {
    const MAX_RULES: usize = 10;
    const MIN_COVERAGE_RATIO: f64 = 0.1; // At least 10% of remaining traffic

    if flows.is_empty() {
        return Vec::new();
    }

    // Pre-filter flows by the alert's protocol category.
    // This focuses analysis on only the traffic that triggered the alert,
    // preventing legitimate traffic in other protocols from skewing results.
    let filtered: Vec<FlowRecord> = if protocol_filter == ProtocolCategory::Any {
        flows.to_vec()
    } else {
        flows
            .iter()
            .filter(|f| {
                let cats = ProtocolCategory::classify(f.protocol, f.tcp_flags, f.dst_port);
                cats.contains(&protocol_filter)
            })
            .cloned()
            .collect()
    };

    if filtered.is_empty() {
        return Vec::new();
    }

    // For specific protocol filters, the filtered flows all share a known
    // protocol/port. Inject those as "forced" fields into every generated rule
    // and exclude them from the candidate search (they're trivially true for
    // 100% of remaining flows and would dominate).
    let (forced_protocol, forced_dst_port): (Option<String>, Option<u16>) = match protocol_filter {
        ProtocolCategory::Any => (None, None),
        ProtocolCategory::TcpSyn => (Some("tcp".to_string()), None),
        ProtocolCategory::Dns => (None, Some(53)),
        ProtocolCategory::Https => (Some("tcp".to_string()), Some(443)),
        other => {
            let n = proto_number(other);
            (if n != 0 { Some(protocol_name(n)) } else { None }, None)
        }
    };

    let mut remaining = filtered;
    let mut rules = Vec::new();

    let mut exclude_fields: u8 = 0;
    if forced_protocol.is_some() {
        exclude_fields |= FieldSet::PROTOCOL;
    }
    if forced_dst_port.is_some() {
        exclude_fields |= FieldSet::DST_PORT;
    }

    // Total bytes in captured flows — represents traffic proportional to
    // current_rate.
    let total_bytes: u64 = remaining.iter().map(|f| f.sampled_bytes()).sum();

    for _ in 0..MAX_RULES {
        if remaining.is_empty() {
            break;
        }

        // Estimate remaining rate after previous rules would be applied.
        // remaining_rate ≈ current_rate * (remaining_bytes / total_bytes)
        // If already below threshold, no more rules needed.
        if total_bytes > 0 && threshold > 0.0 {
            let remaining_bytes: u64 = remaining.iter().map(|f| f.sampled_bytes()).sum();
            let estimated_remaining_rate =
                current_rate * (remaining_bytes as f64 / total_bytes as f64);
            if estimated_remaining_rate < threshold {
                break;
            }
        }

        let candidate = match find_best_candidate(&remaining, MIN_COVERAGE_RATIO, exclude_fields) {
            Some(c) => c,
            None => break,
        };

        // Narrow the destination prefix to a specific host if one dominates.
        let rule_dest_prefix = compute_destination_prefix(&remaining, direction, dest_prefix, 0.8);
        let rule_dest_prefix_str = rule_dest_prefix.to_string();

        // Build the Flow Spec rule from the candidate
        let source_prefix = candidate.src_ip.map(|ip| match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        });

        let mut destination_ports = Vec::new();
        if let Some(port) = candidate.dst_port {
            if port != 0 {
                destination_ports.push(port);
            }
        } else if let Some(port) = forced_dst_port {
            destination_ports.push(port);
        }

        let mut source_ports = Vec::new();
        if let Some(port) = candidate.src_port
            && port != 0
        {
            source_ports.push(port);
        }

        // Use the protocol from the candidate if discovered, otherwise use the forced
        // one
        let protocols = if let Some(proto) = candidate.protocol {
            vec![protocol_name(proto)]
        } else if let Some(ref forced) = forced_protocol {
            vec![forced.clone()]
        } else {
            Vec::new()
        };

        let mut tcp_flags_list = candidate
            .tcp_flags
            .map(tcp_flag_names)
            .unwrap_or_default();

        // For TcpSyn alerts, always include the syn flag
        if protocol_filter == ProtocolCategory::TcpSyn && tcp_flags_list.is_empty() {
            tcp_flags_list.push("syn".to_string());
        }

        // For inbound attacks, source_prefix is the attacker, destination_prefix is the
        // victim. For outbound, it's reversed.
        let (rule_src, rule_dst) = match direction {
            Direction::Inbound => (source_prefix, rule_dest_prefix_str),
            Direction::Outbound => (
                Some(rule_dest_prefix_str),
                candidate
                    .src_ip
                    .map(|ip| match ip {
                        IpAddr::V4(_) => format!("{}/32", ip),
                        IpAddr::V6(_) => format!("{}/128", ip),
                    })
                    .unwrap_or_else(|| dest_prefix.to_string()),
            ),
        };

        rules.push(MitigationRule {
            source_prefix: rule_src,
            destination_prefix: rule_dst,
            destination_ports,
            source_ports,
            protocols,
            tcp_flags: tcp_flags_list,
        });

        // Remove flows matching this candidate
        remaining.retain(|flow| !candidate.matches(flow));
    }

    rules
}
