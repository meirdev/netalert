use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub bytes: u64,
    pub packets: u64,
    pub time_received: u64,
    pub sampling_rate: u32,
}

impl FlowRecord {
    pub fn from_common_flow(flow: &rustflow::CommonFlow) -> Self {
        let received = (flow.time_received_ns.unwrap() / 1_000_000_000) as u64;

        Self {
            src_ip: flow.src_addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            dst_ip: flow.dst_addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            src_port: flow.src_port.unwrap_or(0),
            dst_port: flow.dst_port.unwrap_or(0),
            protocol: flow.proto.unwrap_or(0),
            tcp_flags: flow.tcp_flags.unwrap_or(0),
            bytes: flow.bytes,
            packets: flow.packets,
            time_received: received,
            sampling_rate: flow.sampling_rate.unwrap_or(1),
        }
    }

    pub fn sampled_bytes(&self) -> u64 {
        self.bytes * self.sampling_rate as u64
    }

    pub fn sampled_packets(&self) -> u64 {
        self.packets * self.sampling_rate as u64
    }
}
