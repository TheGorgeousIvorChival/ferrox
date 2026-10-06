//! `Config` with the upstream defaults, and the same derived sizes.

/// Transport tuning. Defaults equal the upstream `init()` block:
/// `Mtu: 1350, Tti: 50, UplinkCapacity: 5, DownlinkCapacity: 20,
/// CwndMultiplier: 1, MaxSendingWindow: 2 * 1024 * 1024`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Maximum transmission unit in bytes.
    pub mtu: u32,
    /// Transmission time interval: the tick quantum, milliseconds.
    pub tti: u32,
    /// Uplink capacity, MiB.
    pub uplink_capacity: u32,
    /// Downlink capacity, MiB.
    pub downlink_capacity: u32,
    /// Congestion window multiplier applied to the computed cwnd.
    pub cwnd_multiplier: u32,
    /// Sending buffer ceiling in bytes.
    pub max_sending_window: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * 1024 * 1024,
        }
    }
}

impl Config {
    /// In-flight byte ceiling for the sending window, in segments.
    #[must_use]
    pub fn sending_in_flight_size(&self) -> u32 {
        let size = self.uplink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        size.max(8)
    }

    /// Sending buffer ceiling in segments.
    #[must_use]
    pub fn sending_buffer_size(&self) -> u32 {
        self.max_sending_window / self.mtu
    }

    /// In-flight byte ceiling for the receiving window, in segments.
    #[must_use]
    pub fn receiving_in_flight_size(&self) -> u32 {
        let size = self.downlink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        size.max(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upstream_defaults_are_these() {
        let c = Config::default();
        assert_eq!(c.mtu, 1350);
        assert_eq!(c.tti, 50);
        assert_eq!(c.uplink_capacity, 5);
        assert_eq!(c.downlink_capacity, 20);
        assert_eq!(c.cwnd_multiplier, 1);
        assert_eq!(c.max_sending_window, 2 * 1024 * 1024);
    }

    #[test]
    fn derived_sizes_match_the_formula() {
        let c = Config::default();
        assert_eq!(c.sending_in_flight_size(), 194);
        assert_eq!(c.sending_buffer_size(), 1553);
        assert_eq!(c.receiving_in_flight_size(), 776);
    }
}
