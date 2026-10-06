//! The wire codec: one enum instead of the Go interface's parallel
//! `parse`/`Serialize`/`ByteSize` triple, byte-identical on the wire.

/// Length of the data segment header up to and including the length field.
pub const DATA_SEGMENT_OVERHEAD: u32 = 18;

/// Maximum ack numbers per segment (the upstream's `ackNumberLimit`).
pub const ACK_NUMBER_LIMIT: usize = 128;

/// Segment purpose byte; values match the upstream wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0` — acknowledgement.
    Ack,
    /// `1` — data.
    Data,
    /// `2` — peer terminated.
    Terminate,
    /// `3` — liveness.
    Ping,
}

impl Command {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            Self::Ack => 0,
            Self::Data => 1,
            Self::Terminate => 2,
            Self::Ping => 3,
        }
    }
}

/// Header flags; bit 0 closes the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentOption(pub u8);

impl SegmentOption {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// The close bit.
    pub const CLOSE: Self = Self(1);

    pub(crate) fn to_byte(self) -> u8 {
        self.0
    }

    /// Whether the close bit is set.
    #[must_use]
    pub fn is_close(self) -> bool {
        self.0 & 1 == 1
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
}

/// A data segment: one application chunk plus the fields its peer needs to
/// advance its ack clock.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataSegment {
    /// Conversation id.
    pub conv: u16,
    /// Header flags.
    pub option: SegmentOption,
    /// Sender's clock at flush.
    pub timestamp: u32,
    /// Sequence number.
    pub number: u32,
    /// First number the sender has not seen acknowledged.
    pub sending_next: u32,
    /// Payload.
    pub payload: Vec<u8>,
    pub(crate) timeout: u32,
    pub(crate) transmit: u32,
}

impl DataSegment {
    /// The payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.payload
    }

    fn parse(conv: u16, option: SegmentOption, buf: &[u8]) -> Option<(Self, &[u8])> {
        // Upstream requires at least 15 bytes here — deliberately not 14,
        // so a zero-length payload cannot round-trip. See `segment.go`.
        if buf.len() < 15 {
            return None;
        }
        let mut cur = Cursor { buf };
        let timestamp = cur.u32()?;
        let number = cur.u32()?;
        let sending_next = cur.u32()?;
        let data_len = cur.u16()? as usize;
        let payload = cur.take(data_len)?;
        Some((
            Self {
                conv,
                option,
                timestamp,
                number,
                sending_next,
                payload: payload.to_vec(),
                timeout: 0,
                transmit: 0,
            },
            cur.buf,
        ))
    }

    pub(crate) fn byte_size(&self) -> usize {
        DATA_SEGMENT_OVERHEAD as usize + self.payload.len()
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(Command::Data.to_byte());
        out.push(self.option.to_byte());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(&self.sending_next.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
    }
}

/// An acknowledgement segment: the receiver's clock, its next-expected
/// number and the list of explicitly-acknowledged numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckSegment {
    /// Conversation id.
    pub conv: u16,
    /// Header flags.
    pub option: SegmentOption,
    /// Last number the sender may use (`next_number + window_size`).
    pub receiving_window: u32,
    /// Next number the receiver wants.
    pub receiving_next: u32,
    /// Receiver's clock.
    pub timestamp: u32,
    /// Explicitly acknowledged numbers.
    pub numbers: Vec<u32>,
    limit: usize,
}

impl AckSegment {
    /// A fresh ack segment with capacity `limit`; upstream clamps to 1..=128.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            conv: 0,
            option: SegmentOption::NONE,
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            numbers: Vec::new(),
            limit: limit.clamp(1, ACK_NUMBER_LIMIT),
        }
    }

    /// Upstream `PutNumber`.
    pub fn put_number(&mut self, number: u32) {
        self.numbers.push(number);
    }

    /// Upstream `PutTimestamp`: the newest on the wrap-aware comparison.
    pub fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFF_FFFF {
            self.timestamp = timestamp;
        }
    }

    /// Full at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.numbers.len() == self.limit
    }

    /// Empty list.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.numbers.is_empty()
    }

    pub(crate) fn byte_size(&self) -> usize {
        17 + self.numbers.len() * 4
    }

    fn parse(conv: u16, option: SegmentOption, buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 13 {
            return None;
        }
        let mut cur = Cursor { buf };
        let receiving_window = cur.u32()?;
        let receiving_next = cur.u32()?;
        let timestamp = cur.u32()?;
        let count = cur.u8()? as usize;
        let mut numbers = Vec::with_capacity(count);
        for _ in 0..count {
            numbers.push(cur.u32()?);
        }
        Some((
            Self {
                conv,
                option,
                receiving_window,
                receiving_next,
                timestamp,
                numbers,
                limit: ACK_NUMBER_LIMIT,
            },
            cur.buf,
        ))
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(Command::Ack.to_byte());
        out.push(self.option.to_byte());
        out.extend_from_slice(&self.receiving_window.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.numbers.len() as u8);
        for number in &self.numbers {
            out.extend_from_slice(&number.to_be_bytes());
        }
    }
}

/// A command-only segment: ping, terminate, or any unrecognised command
/// byte (upstream parses every unknown `cmd` as this shape when 12 payload
/// bytes follow, and keeps the raw byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmdOnlySegment {
    /// Conversation id.
    pub conv: u16,
    /// The raw command byte, preserved verbatim (upstream `Command` is a
    /// `byte`, so every value round-trips; `u8` keeps that bit-exact).
    pub cmd: u8,
    /// Header flags.
    pub option: SegmentOption,
    /// Sender's first unacknowledged number.
    pub sending_next: u32,
    /// Receiver's next expected number.
    pub receiving_next: u32,
    /// Peer's current RTO estimate.
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    /// Empty instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            conv: 0,
            cmd: Command::Ping.to_byte(),
            option: SegmentOption::NONE,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 0,
        }
    }

    /// The command byte as a known variant, when it names one.
    #[must_use]
    pub fn kind(&self) -> Option<Command> {
        match self.cmd {
            0 => Some(Command::Ack),
            1 => Some(Command::Data),
            2 => Some(Command::Terminate),
            3 => Some(Command::Ping),
            _ => None,
        }
    }

    pub(crate) fn byte_size() -> usize {
        16
    }

    fn parse(conv: u16, cmd: u8, option: SegmentOption, buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 12 {
            return None;
        }
        let mut cur = Cursor { buf };
        let sending_next = cur.u32()?;
        let receiving_next = cur.u32()?;
        let peer_rto = cur.u32()?;
        Some((
            Self {
                conv,
                cmd,
                option,
                sending_next,
                receiving_next,
                peer_rto,
            },
            cur.buf,
        ))
    }

    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(self.cmd);
        out.push(self.option.to_byte());
        out.extend_from_slice(&self.sending_next.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.peer_rto.to_be_bytes());
    }
}

impl Default for CmdOnlySegment {
    fn default() -> Self {
        Self::new()
    }
}

/// One parsed segment: data, ack, or command-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// A data chunk.
    Data(DataSegment),
    /// An ack batch.
    Ack(AckSegment),
    /// Ping/terminate/unknown.
    CmdOnly(CmdOnlySegment),
}

impl Segment {
    /// Conversation id.
    #[must_use]
    pub fn conversation(&self) -> u16 {
        match self {
            Self::Data(s) => s.conv,
            Self::Ack(s) => s.conv,
            Self::CmdOnly(s) => s.conv,
        }
    }

    /// Purpose byte, when it names a known variant (`None` for an unknown
    /// byte, which upstream also round-trips verbatim).
    #[must_use]
    pub fn command(&self) -> Option<Command> {
        match self {
            Self::Data(_) => Some(Command::Data),
            Self::Ack(_) => Some(Command::Ack),
            Self::CmdOnly(s) => s.kind(),
        }
    }

    /// Serialized length.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Data(s) => s.byte_size(),
            Self::Ack(s) => s.byte_size(),
            Self::CmdOnly(_) => CmdOnlySegment::byte_size(),
        }
    }

    /// Serialize.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Self::Data(s) => s.serialize(out),
            Self::Ack(s) => s.serialize(out),
            Self::CmdOnly(s) => s.serialize(out),
        }
    }

    /// Header flags.
    #[must_use]
    pub fn option(&self) -> SegmentOption {
        match self {
            Self::Data(s) => s.option,
            Self::Ack(s) => s.option,
            Self::CmdOnly(s) => s.option,
        }
    }
}

/// Parse one segment off the front of `buf`; `None` on a bad segment.
/// Upstream maps every unknown command byte to the command-only shape.
#[must_use]
pub fn read_segment(buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes(buf[0..2].try_into().ok()?);
    let cmd_byte = buf[2];
    let opt = SegmentOption(buf[3]);
    let rest = &buf[4..];
    match cmd_byte {
        0 => {
            let (seg, tail) = AckSegment::parse(conv, opt, rest)?;
            Some((Segment::Ack(seg), tail))
        }
        1 => {
            let (seg, tail) = DataSegment::parse(conv, opt, rest)?;
            Some((Segment::Data(seg), tail))
        }
        _ => {
            let (seg, tail) = CmdOnlySegment::parse(conv, cmd_byte, opt, rest)?;
            Some((Segment::CmdOnly(seg), tail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_segment_round_trips() {
        let seg = DataSegment {
            conv: 1,
            option: SegmentOption::NONE,
            timestamp: 3,
            number: 4,
            sending_next: 5,
            payload: b"abcd".to_vec(),
            timeout: 0,
            transmit: 0,
        };
        let mut buf = Vec::new();
        Segment::Data(seg.clone()).serialize(&mut buf);
        assert_eq!(buf.len(), DATA_SEGMENT_OVERHEAD as usize + 4);
        let (got, rest) = read_segment(&buf).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(got, Segment::Data(seg));
    }

    #[test]
    fn an_ack_segment_round_trips() {
        let mut seg = AckSegment::new(128);
        seg.conv = 7;
        seg.receiving_window = 100;
        seg.receiving_next = 42;
        seg.put_timestamp(999);
        seg.put_number(1);
        seg.put_number(2);
        let mut buf = Vec::new();
        Segment::Ack(seg.clone()).serialize(&mut buf);
        let (got, _) = read_segment(&buf).unwrap();
        match got {
            Segment::Ack(a) => {
                assert_eq!(a.numbers, vec![1, 2]);
                assert_eq!(a.receiving_window, 100);
                assert_eq!(a.receiving_next, 42);
                assert_eq!(a.timestamp, 999);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn the_command_only_layout_is_sixteen_bytes() {
        let mut seg = CmdOnlySegment::new();
        seg.conv = 9;
        seg.cmd = Command::Terminate.to_byte();
        seg.sending_next = 1;
        seg.receiving_next = 2;
        seg.peer_rto = 3;
        let mut buf = Vec::new();
        Segment::CmdOnly(seg).serialize(&mut buf);
        assert_eq!(buf, [0, 9, 2, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    }

    #[test]
    fn unknown_command_bytes_round_trip_verbatim() {
        // Build the bytes manually: cmd byte 250.
        let mut raw = vec![0, 3, 250, 0];
        raw.extend_from_slice(&1u32.to_be_bytes());
        raw.extend_from_slice(&2u32.to_be_bytes());
        raw.extend_from_slice(&3u32.to_be_bytes());
        let (seg, _) = read_segment(&raw).unwrap();
        match seg {
            Segment::CmdOnly(c) => assert_eq!(c.cmd, 250),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn a_zero_length_payload_does_not_round_trip() {
        // The upstream's 15-byte minimum means a header-only data segment
        // fails to parse: that is the format, ported as-is.
        let mut raw = vec![0, 1, 1, 0];
        raw.extend_from_slice(&3u32.to_be_bytes());
        raw.extend_from_slice(&4u32.to_be_bytes());
        raw.extend_from_slice(&5u32.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        assert!(read_segment(&raw).is_none());
    }
}
