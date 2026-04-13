#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    pub timestamp: u64,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}

impl Bucket {
    pub fn reset(&mut self, timestamp: u64) {
        self.timestamp = timestamp;
        self.bytes = 0;
        self.packets = 0;
        self.flows = 0;
    }
}

#[derive(Debug, Clone)]
pub struct RingBuffer {
    buckets: Vec<Bucket>,
}

impl RingBuffer {
    pub fn new(window_secs: usize) -> Self {
        Self {
            buckets: vec![Bucket::default(); window_secs],
        }
    }

    fn bucket_index(&self, timestamp: u64) -> usize {
        (timestamp as usize) % self.buckets.len()
    }

    fn get_or_reset_bucket(&mut self, timestamp: u64) -> &mut Bucket {
        let idx = self.bucket_index(timestamp);
        let bucket = &mut self.buckets[idx];

        if bucket.timestamp != timestamp {
            bucket.reset(timestamp);
        }

        bucket
    }

    pub fn add_instant_flow(&mut self, timestamp: u64, bytes: u64, packets: u64) {
        let bucket = self.get_or_reset_bucket(timestamp);
        bucket.bytes += bytes;
        bucket.packets += packets;
        bucket.flows += 1;
    }

    pub fn compute_rates(&self, current_time: u64) -> (f64, f64, f64) {
        let window = self.buckets.len();
        let mut total_bytes: u64 = 0;
        let mut total_packets: u64 = 0;
        let mut total_flows: u64 = 0;
        let mut valid_buckets: usize = 0;

        for i in 0..window {
            let t = current_time.saturating_sub(i as u64);
            let idx = self.bucket_index(t);
            let bucket = &self.buckets[idx];

            if bucket.timestamp == t {
                total_bytes += bucket.bytes;
                total_packets += bucket.packets;
                total_flows += bucket.flows;
                valid_buckets += 1;
            }
        }

        if valid_buckets == 0 {
            return (0.0, 0.0, 0.0);
        }

        let window = window as f64;
        let bps = (total_bytes as f64 * 8.0) / window;
        let pps = total_packets as f64 / window;
        let fps = total_flows as f64 / window;

        (bps, pps, fps)
    }
}
