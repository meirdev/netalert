# NetAlert

NetAlert monitors network traffic flows from routers and network devices, evaluates traffic rates against configurable thresholds, and generates alerts with BGP Flow Spec mitigation recommendations for DDoS defense.

## Features

- **NetFlow v5/v9/IPFIX and sFlow** receiver with per-exporter sampling rate correction
- **Configurable thresholds** for bits/sec, packets/sec, and flows/sec per prefix, protocol, and direction
- **Alert state machine** with hysteresis — configurable trigger and recovery durations to avoid flapping
- **BGP Flow Spec mitigation analysis** — automatically analyzes captured flows to suggest specific filtering rules
- **Prometheus metrics** endpoint for integration with monitoring stacks

### CLI Options

```
netalert [OPTIONS]

Options:
  --config <CONFIG>         Config file path [default: config.yaml]
  --netflow-port <PORT>     NetFlow listen port [default: 2055]
  --sflow-port <PORT>       sFlow listen port [default: 6343]
  --bind-addr <ADDR>        Bind address [default: 0.0.0.0]
  --log-level <LEVEL>       Log level [default: info]
  --metrics-addr <ADDR>     Prometheus metrics address [default: 0.0.0.0:9090]
```

## Configuration

NetAlert is configured via a YAML file.

```yaml
global:
  evaluation_interval: 1s # How often to evaluate thresholds
  window: 10s # Sliding window for rate calculation
  alert_script: /etc/netalert/alert.sh # Script called on alert events
  capture_buffer_size: 500 # Max flows captured per rule for analysis
  mitigation_update_interval: 30s # Re-analysis interval while alert is firing

exporters:
  edge-router-1:
    address: 10.1.1.1
    sampling_rate: 1000

alert_policies:
  default_ddos:
    trigger_for: 3s # Threshold must be exceeded for 3s to fire
    recover_for: 30s # Must drop below recovery threshold for 30s to resolve

rules:
  - prefix: 10.0.0.0/24
    labels:
      segment: customer
    alert_policy: default_ddos
    thresholds:
      any:
        inbound:
          metrics:
            bps:
              trigger: 300000000 # 300 Mbps
              recover: 200000000 # 200 Mbps
            pps:
              trigger: 100000
```

### Supported Protocols

`any`, `tcp`, `udp`, `icmp`, `gre`, `esp`, `tcp_syn`, `dns`, `https`

### Supported Directions

`inbound` (destination IP matches prefix), `outbound` (source IP matches prefix)

### Supported Metrics

| Metric | Description        |
| ------ | ------------------ |
| `bps`  | Bits per second    |
| `pps`  | Packets per second |
| `fps`  | Flows per second   |

Each metric supports `trigger` and `recover` thresholds. If `recover` is omitted, it defaults to the `trigger` value.

## Alert Script

When an alert triggers, updates, or resolves, NetAlert calls the configured `alert_script` with a JSON payload on stdin:

```json
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "trigger",
  "prefix": "10.0.0.0/24",
  "protocol": "tcp",
  "direction": "inbound",
  "metric": "bps",
  "value": 450000000,
  "threshold": 300000000,
  "labels": { "segment": "customer" },
  "mitigation_rules": [
    {
      "source_prefix": "192.0.2.10/32",
      "destination_prefix": "10.0.0.5/32",
      "destination_ports": [80],
      "protocols": ["tcp"],
      "tcp_flags": ["syn"]
    }
  ]
}
```

The `mitigation_rules` field contains suggested BGP Flow Spec rules derived from analyzing captured flows during the alert.

## Prometheus Metrics

Metrics are exposed at `http://<metrics-addr>/metrics`:

```
netalert_bps{prefix="10.0.0.0/24",protocol="tcp",direction="inbound",segment="customer"} 45000000.0
netalert_pps{prefix="10.0.0.0/24",protocol="tcp",direction="inbound",segment="customer"} 50000.0
netalert_fps{prefix="10.0.0.0/24",protocol="tcp",direction="inbound",segment="customer"} 100.0
```

Rule labels are included as metric dimensions.

## Architecture

NetAlert runs as an async multi-task daemon:

1. **Receivers** — Listen for NetFlow and sFlow on UDP, parse flows, apply sampling corrections
2. **Processor** — Matches flows against rule prefixes, classifies protocols, buffers into ring buffers and capture buffers
3. **Evaluator** — Periodically computes rates from sliding windows, evaluates alert state machines, triggers scripts, publishes metrics
4. **Metrics server** — Serves Prometheus-format metrics over HTTP
