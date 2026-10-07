//! Flow-control credit for one HTTP/2 stream and its connection, in one type.
//!
//! The peer grants credit in two places — its `INITIAL_WINDOW_SIZE` setting and
//! its `WINDOW_UPDATE` frames — and this lane spends it against both at once,
//! because a DATA frame that the connection window refuses is refused at the
//! stream too. Refilling is the caller's business; this only answers whether a
//! frame of a given size may go out now and how much is left afterwards.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    stream: i64,
    connection: i64,
}

impl Window {
    /// Both windows start at the protocol default until the peer's settings say
    /// otherwise; a peer that never sends settings gets the default.
    #[must_use]
    pub const fn new(stream: i64, connection: i64) -> Self {
        Self { stream, connection }
    }

    /// Adopts the peer's `INITIAL_WINDOW_SIZE`, which applies to streams that
    /// were not open yet and so cannot be moved by an already-sent update.
    pub fn reset_stream(&mut self, size: u32) {
        self.stream = i64::from(size);
    }

    pub fn add_stream(&mut self, increment: u32) {
        self.stream = self.stream.saturating_add(i64::from(increment));
    }

    pub fn add_connection(&mut self, increment: u32) {
        self.connection = self.connection.saturating_add(i64::from(increment));
    }

    #[must_use]
    pub fn allows(&self, len: u32) -> bool {
        let len = i64::from(len);
        self.stream >= len && self.connection >= len
    }

    /// Spends `len` bytes of credit. Only call this after `allows`.
    pub fn take(&mut self, len: u32) {
        let len = i64::from(len);
        self.stream -= len;
        self.connection -= len;
    }

    #[must_use]
    pub fn stream(&self) -> u32 {
        self.stream.max(0) as u32
    }

    #[must_use]
    pub fn connection(&self) -> u32 {
        self.connection.max(0) as u32
    }
}

/// HTTP/2 spends at most a peer-advertised maximum frame size per DATA frame, so
/// a slice longer than that is several frames rather than one.
#[must_use]
pub fn frame_size(available: usize, max_frame: usize) -> u32 {
    let capped = available.min(max_frame.max(1));
    u32::try_from(capped).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_the_stream_allows_but_the_connection_does_not_may_not_go_out() {
        let window = Window::new(100, 10);
        assert!(!window.allows(11), "the connection is the tighter window");
        assert!(window.allows(10));
        assert!(!Window::new(10, 100).allows(11), "and so is the stream");
    }

    #[test]
    fn spending_credit_leaves_exactly_what_is_left() {
        let mut window = Window::new(100, 100);
        window.take(30);
        assert_eq!((window.stream(), window.connection()), (70, 70));
        window.add_stream(5);
        assert_eq!(window.stream(), 75);
        assert_eq!(window.connection(), 70);
    }

    #[test]
    fn a_settings_change_moves_the_stream_window_without_moving_the_connection() {
        let mut window = Window::new(65_535, 65_535);
        window.reset_stream(1_048_576);
        assert_eq!(window.stream(), 1_048_576);
        assert_eq!(window.connection(), 65_535);
    }

    #[test]
    fn credit_never_wraps_even_when_the_peer_over_announces() {
        let mut window = Window::new(i64::MAX - 1, i64::MAX - 1);
        window.add_stream(u32::MAX);
        window.add_connection(u32::MAX);
        assert_eq!((window.stream(), window.connection()), (u32::MAX, u32::MAX));
    }

    #[test]
    fn one_frame_is_at_most_the_peer_maximum() {
        assert_eq!(frame_size(1_000_000, 16_384), 16_384);
        assert_eq!(frame_size(100, 16_384), 100);
        assert_eq!(
            frame_size(1_000_000, 0),
            1,
            "a peer that allows nothing gets one byte"
        );
        assert_eq!(frame_size(usize::MAX, 16_384), 16_384);
    }
}
