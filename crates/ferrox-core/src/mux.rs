//! Multiplexing: many logical streams inside one proxy stream.
//!
//! One `VLESS` or `VMess` stream is asked for a mux connection; after that the
//! frames that travel inside it carry their own destinations and session ids, and
//! one TCP connection carries many conversations. This is the frame layer and the
//! session bookkeeping — not the socket loop, which belongs to the application.
//!
//! # Why this rung exists
//!
//! It is the one connection method Xray-core, sing-box and `PattNG` all carry
//! that this workspace had none of, and the one that *multiplies* the rest: mux
//! rides on every carrier, so landing it turns each row of
//! [`crate::transport`]'s matrix into a family rather than adding a row.
//! xray-rust, the fourth implementation, has no mux at all and rejects
//! `{"mux": {"enabled": true}}` at config-parse time — a refusal is the shape
//! this gap had here until now, and a worse one.
//!
//! # The format, which is all this file has to get right
//!
//! ```text
//! frame  := meta_len:u16be  meta[meta_len]  [ len:u16be  payload[len] ]
//! meta   := id:u16be  status:u8  option:u8  [ext]
//! ```
//!
//! `meta_len` counts the metadata and nothing else — not itself, not the chunk.
//! Four bytes of it are fixed, so `meta_len == 4` is a frame with no address in
//! it. `option` is a bitmask: bit 0 says a chunk follows the metadata, bit 1 says
//! a sub-stream ended in error.
//!
//! `status` decides what `ext` may be, and nothing else does:
//!
//! | status | `ext` |
//! | - | - |
//! | `New` (1) | `network(1) port(2) atyp(1) addr`, then one of: nothing, eight bytes of NAT identity on a UDP frame, or a reverse-mux bridge's source and local addresses |
//! | `Keep` (2) | nothing, or `network port atyp addr` again when a datagram brought its own destination — recognised by the network byte being `0x02` |
//! | `End` (3) | nothing |
//! | `KeepAlive` (4) | nothing, optionally followed by one chunk to discard |
//!
//! `network` is `0x01` for `TCP` and `0x02` for `UDP`. The address field itself
//! is [`crate::addr`]'s, and the port sits immediately before the family byte —
//! in both this format and `VLESS`'s, which is why one codec serves both.
//!
//! # What this leaves out, and why that is a subset rather than a gap
//!
//! * **Reverse mux.** Decoding one is four lines, so a peer that sends one is
//!   framed correctly instead of dropped; *emitting* one is a bridge feature
//!   this core has no use for, and [`Outgoing`] cannot express it. The decoder
//!   is a strict superset of the encoder, and
//!   [`Incoming::to_outgoing`] is where that asymmetry is stated as code.
//! * **`KeepAlive` frames.** Never written by any of the four implementations —
//!   receive-only — and named here only so the reader handles one.
//! * **The NAT session map.** Eight bytes of a `New` frame's identity are carried
//!   because they are part of the frame; the global map that turns them into a
//!   reusable UDP association, with its sixty-second expiry, belongs to a UDP
//!   path this crate does not own.
//! * **Worker pools, round-robin pickers, backpressure pipes.** Runtime, not
//!   framing. [`Ids`] and [`Sessions`] are the bookkeeping a runtime needs and
//!   nothing more.
//!
//! # Where the four implementations spend what this does not
//!
//! Xray-core reads `meta_len` bytes into a fresh pooled 8 KiB buffer, then
//! allocates *another* pooled 8 KiB buffer per address to pull out at most
//! eighteen bytes through three separate reads — up to three per `New` frame —
//! and writes each frame header into a third 8 KiB buffer of which eight to
//! twenty bytes are used, each of which then becomes its own `writev` iovec. It
//! keeps six copies of the address codec in one file, recomputes the frame length
//! four to six times per frame across `IsEmpty`/`Len` calls, and allocates a
//! two-byte slice for the chunk length on both sides of every data frame.
//!
//! sing-box does not frame at all: it delegates to a third-party stream
//! multiplexer and adds a session handshake, a padding layer and a bandwidth
//! exchange on top, in three wire protocols where this format is the one both
//! upstreams already speak on the `VLESS` and `VMess` paths.
//!
//! xray-rust has no implementation to compare against and `PattNG` configures
//! Xray-core's rather than carrying it, so neither contributes a shape here.
//!
//! What replaces all of that: one pass over a borrowed slice in each direction,
//! no allocation on either, no copy of the metadata, and a length that is
//! computed once — [`Outgoing::meta_len`] is the only function in the crate that
//! knows what a metadata length is, and [`decode`] re-derives it from the same
//! rules rather than from a second description of them.
//!
//! Three of upstream's shapes are not reproduced because they are bugs the
//! format does not require: its `u16` session counter wraps at 65536 and
//! overwrites a live session with id zero ([`Ids`] refuses instead), its writer
//! can emit metadata of up to 781 bytes while its own reader drops any peer
//! sending more than 512 ([`META_MAX`] accepts everything its writer can produce),
//! and its `New` encoder has no default arm, so a target that is neither `TCP`
//! nor `UDP` is written with no network byte at all — unrepresentable here,
//! because [`Target::network`] is an enum.
//!
//! # Licence
//!
//! Parsed, not copied. A frame layout is a wire format; no Xray-core, sing-box,
//! xray-rust or `PattNG` line or test appears here, and every golden vector
//! below is spelled out from the table at the top of this file with its
//! arithmetic shown, so a reviewer can check it against the pinned upstream by
//! eye rather than take this module's word for it.

use std::fmt;

use crate::addr::{self, Addr};

/// Option bit: a chunk follows the metadata.
pub const DATA: u8 = 0x01;
/// Option bit: the sub-stream ended because of an error.
pub const ERROR: u8 = 0x02;

/// Bytes of metadata in every frame: the session id, the status, the option.
pub const FIXED: usize = 4;

/// Bytes of the NAT identity a `New` frame may carry.
pub const GLOBAL_ID: usize = 8;

/// The largest metadata a frame can carry: three addresses and a NAT identity,
/// plus the fixed four.
///
/// Every implementation here writes three addresses into a `New` frame — target,
/// source, local — so this is the ceiling over the whole format rather than over
/// what this crate emits. It is 781, which is the point: upstream's writer can
/// produce 781 and its reader drops anything above 512, so a reverse-mux peer
/// with long domains is disconnected by the reader for a frame its own writer
/// made. The identity does not add to it, because a `New` frame carries either
/// reflection or an identity and never both.
pub const META_MAX: usize = FIXED + 3 * (1 + 2 + 1 + addr::MAX_DOMAIN);

/// The largest payload one chunk carries, which is the buffer size the four
/// implementations split writes at.
pub const CHUNK_MAX: usize = 8192;

/// How many session ids the sixteen-bit field holds.
pub const ID_SPACE: usize = 1 << 16;

/// The most sessions a connection carries unless told otherwise, which is the
/// default every one of these implementations uses.
pub const DEFAULT_CAP: usize = 8;

/// A frame's status byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Opens a sub-stream and names its destination.
    New,
    /// Carries bytes for a sub-stream that is already open.
    Keep,
    /// Half-closes a sub-stream.
    End,
    /// A liveness frame. Read, never needed, and so never written here.
    KeepAlive,
}

impl Status {
    /// The status byte, or `None` for one the format does not name.
    ///
    /// An unnamed status is refused rather than skipped. Upstream ignores it,
    /// which does not skip it: the chunk length after the metadata is then never
    /// read, so the next frame is parsed from the middle of this one's payload.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::New),
            0x02 => Some(Self::Keep),
            0x03 => Some(Self::End),
            0x04 => Some(Self::KeepAlive),
            _ => None,
        }
    }

    /// The status byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::New => 0x01,
            Self::Keep => 0x02,
            Self::End => 0x03,
            Self::KeepAlive => 0x04,
        }
    }
}

/// Which transport a sub-stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A stream.
    Tcp,
    /// Datagrams.
    Udp,
}

impl Network {
    /// The network byte, or `None` for one the format does not name.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }

    /// The network byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Tcp => 0x01,
            Self::Udp => 0x02,
        }
    }
}

/// Where a sub-stream is opened to, in the order this format writes it:
/// network, port, then the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    /// Whether the sub-stream is a stream or datagrams.
    pub network: Network,
    /// Destination port, before the family byte.
    pub port: u16,
    /// Destination address.
    pub addr: Addr<'a>,
}

impl<'a> Target<'a> {
    /// Classify `host` and pair it with a network and a port.
    #[must_use]
    pub fn of(network: Network, host: &'a str, port: u16) -> Self {
        Self {
            network,
            port,
            addr: Addr::of(host),
        }
    }

    /// Bytes on the wire: network, port, address.
    #[must_use]
    pub const fn wire_len(self) -> usize {
        1 + 2 + self.addr.wire_len()
    }

    /// Write the network byte, the big-endian port and the address.
    ///
    /// # Panics
    ///
    /// If `out` is shorter than [`Self::wire_len`].
    #[inline]
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        assert!(out.len() >= self.wire_len(), "mux target buffer too short");
        let mut o = 0;
        out[o] = self.network.byte();
        o += 1;
        out[o..o + 2].copy_from_slice(&self.port.to_be_bytes());
        o += 2;
        o + self.addr.encode_into(&mut out[o..])
    }

    /// Read one target off the front of `buf`, with the bytes it used.
    ///
    /// `buf` is `&'a` because [`Addr::take`] hands back a slice of it, so the
    /// target a caller gets is a view of the caller's own frame rather than a
    /// copy of it. `#[inline]` for the same reason as there: three calls to this
    /// for a bridge's frame, across a crate boundary.
    #[inline]
    pub fn take(buf: &'a [u8]) -> Result<(Self, usize), Error> {
        let Some((&network, rest)) = buf.split_first() else {
            return Err(Error::Truncated);
        };
        let Some(network) = Network::from_byte(network) else {
            return Err(Error::Network(network));
        };
        // `split_first_chunk` hands back the tail, not a count, so the two bytes
        // it took are counted here rather than measured off it.
        let Some((&[hi, lo], after)) = rest.split_first_chunk::<2>() else {
            return Err(Error::Truncated);
        };
        let (addr, used) = Addr::take(after).map_err(|e| match e {
            addr::FamilyError::Unknown(byte) => Error::Family(byte),
            addr::FamilyError::Short => Error::Truncated,
        })?;
        Ok((
            Self {
                network,
                port: u16::from_be_bytes([hi, lo]),
                addr,
            },
            1 + 2 + used,
        ))
    }
}

/// A frame to write: exactly the shapes this core emits.
///
/// [`Incoming`] is the superset, and the difference is one field — a reverse-mux
/// peer is framed rather than dropped, but no frame this type can hold would ever
/// claim to be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outgoing<'a> {
    /// Session this frame belongs to.
    pub id: u16,
    /// What the frame does.
    pub status: Status,
    /// [`DATA`] and [`ERROR`].
    pub options: u8,
    /// The destination: on [`Status::New`] the sub-stream's own, on
    /// [`Status::Keep`] a datagram's. `None` on [`Status::End`] and
    /// [`Status::KeepAlive`], which carry nothing after the fixed four bytes.
    pub target: Option<Target<'a>>,
    /// The peer's NAT identity, on a `New` UDP frame and nowhere else.
    pub global_id: Option<[u8; GLOBAL_ID]>,
}

impl Outgoing<'_> {
    /// A frame with no metadata beyond the fixed four bytes.
    #[must_use]
    pub const fn bare(id: u16, status: Status, options: u8) -> Self {
        Self {
            id,
            status,
            options,
            target: None,
            global_id: None,
        }
    }

    /// Whether [`DATA`] is set, which is what says a chunk follows.
    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.options & DATA != 0
    }

    /// Metadata bytes, not counting the two that count them.
    ///
    /// The one place in the crate that knows what a metadata length is:
    /// [`decode`] re-derives it from the same rules, and `encode_into` writes
    /// the number this returns rather than recomputing it after the fact.
    #[must_use]
    #[inline]
    pub fn meta_len(&self) -> usize {
        let identity = if self.global_id.is_some() {
            GLOBAL_ID
        } else {
            0
        };
        FIXED + self.target.map_or(0, Target::wire_len) + identity
    }

    /// Bytes the whole frame occupies, chunk included.
    #[must_use]
    pub fn frame_len(&self, data_len: usize) -> usize {
        let chunk = if self.has_data() { 2 + data_len } else { 0 };
        2 + self.meta_len() + chunk
    }

    /// Whether this status may be followed by a target, which the format derives
    /// from the status and nothing else.
    #[must_use]
    pub const fn carries_target(&self) -> bool {
        match self.status {
            Status::New => true,
            Status::Keep => self.target.is_some(),
            Status::End | Status::KeepAlive => false,
        }
    }

    /// Write the whole frame — the length, the metadata, and the chunk when
    /// `data` is one — returning the bytes written.
    ///
    /// # Panics
    ///
    /// If the frame disagrees with itself in a way the format cannot carry: a
    /// target on a status that may not have one, a stream `Keep` that carries a
    /// destination, a NAT identity anywhere but a `New` UDP frame, metadata past
    /// [`META_MAX`], a payload longer than [`CHUNK_MAX`], or a buffer shorter than
    /// [`Self::frame_len`]. Each is refused at the encode rather than emitted as
    /// a frame a peer has to drop the connection over.
    ///
    /// The metadata bound is reachable even though [`crate::addr::Addr::of`] cuts
    /// an over-long domain: [`Addr::Name`] is a public variant, so a caller can
    /// build one the classifier would not have produced.
    ///
    /// `#[inline]` because this is twenty-odd instructions of stores crossing a
    /// crate boundary, and it sits on the per-frame path. Gate 6 measured it at
    /// 0.62x-0.78x without this, against a reference that lives beside its
    /// caller and is therefore inlined whether it asks to be or not — so the
    /// ratio was measuring a call, not an algorithm. [`Self::meta_len`] and
    /// [`Target::encode_into`] are marked for the same reason.
    #[inline]
    pub fn encode_into(&self, data: Option<&[u8]>, out: &mut [u8]) -> usize {
        assert!(
            self.carries_target() == self.target.is_some(),
            "the status decides whether a target follows, and this frame disagrees with itself"
        );
        assert!(
            self.status != Status::Keep || self.target.is_none_or(|t| t.network == Network::Udp),
            "only a datagram carries its own destination"
        );
        assert!(
            self.global_id.is_none()
                || (self.status == Status::New
                    && self.target.is_some_and(|t| t.network == Network::Udp)),
            "the NAT identity rides a new UDP frame and nowhere else"
        );
        assert_eq!(
            self.has_data(),
            data.is_some(),
            "the data option and the payload have to agree"
        );
        let payload = data.unwrap_or(&[]);
        assert!(
            payload.len() <= CHUNK_MAX,
            "mux chunk longer than a length field"
        );
        // One call, and the buffer bound derived from it. Asking
        // `frame_len` here — which is what this did — recomputed the metadata
        // length, so the function whose whole claim is that one place knows
        // that number was asking twice.
        let meta = self.meta_len();
        assert!(
            meta <= META_MAX,
            "mux metadata longer than the format allows"
        );
        let chunk = if self.has_data() {
            2 + payload.len()
        } else {
            0
        };
        assert!(out.len() >= 2 + meta + chunk, "mux frame buffer too short");

        let mut o = 2;
        out[o..o + 2].copy_from_slice(&self.id.to_be_bytes());
        o += 2;
        out[o] = self.status.byte();
        o += 1;
        out[o] = self.options;
        o += 1;
        if let Some(target) = self.target {
            o += target.encode_into(&mut out[o..]);
        }
        if let Some(identity) = self.global_id {
            out[o..o + GLOBAL_ID].copy_from_slice(&identity);
            o += GLOBAL_ID;
        }
        debug_assert_eq!(
            o - 2,
            meta,
            "the length came from one function and the writes agree"
        );
        out[..2].copy_from_slice(&(meta as u16).to_be_bytes());

        if self.has_data() {
            out[o..o + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            o += 2;
            out[o..o + payload.len()].copy_from_slice(payload);
            o += payload.len();
        }
        o
    }
}

/// What a peer writes after a [`Status::New`] frame's target address.
///
/// Three shapes are possible — nothing, eight bytes of NAT identity, or a
/// bridge's source and local addresses — and no byte distinguishes the last two,
/// because an address and an identity both begin with bytes that could be either.
/// Upstream threads a per-connection context flag for this; a decoder that
/// guessed would mis-frame every peer of the wrong kind, so it is an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewTail {
    /// A forward peer: nothing, or eight bytes of identity on a UDP frame.
    Forward,
    /// A reverse-mux bridge: where the request came from, and where it was
    /// accepted if a third address follows.
    Reverse,
}

/// Where a bridged request came from and where it was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reflection<'a> {
    /// The address and port the request came from.
    pub source: Target<'a>,
    /// The address and port it was accepted on, when the peer sent one.
    pub local: Option<Target<'a>>,
}

/// A frame read off the wire: a superset of what [`Outgoing`] can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming<'a> {
    /// Session this frame belongs to.
    pub id: u16,
    /// What the frame does.
    pub status: Status,
    /// [`DATA`] and [`ERROR`].
    pub options: u8,
    /// The destination, on the same terms as [`Outgoing::target`].
    pub target: Option<Target<'a>>,
    /// The peer's NAT identity, on a `New` UDP frame and nowhere else.
    pub global_id: Option<[u8; GLOBAL_ID]>,
    /// A bridge's reflection, which this core reads but never writes.
    pub reflection: Option<Reflection<'a>>,
    /// The payload, present exactly when [`DATA`] is set. A zero-length payload
    /// is a real frame; upstream's chunk reader maps it to end-of-stream, which
    /// is the caller's decision to make rather than the codec's.
    pub data: Option<&'a [u8]>,
}

impl<'a> Incoming<'a> {
    /// Whether [`DATA`] was set.
    #[must_use]
    pub const fn has_data(&self) -> bool {
        self.options & DATA != 0
    }

    /// The frame this connection would send back, or `None` when the peer sent a
    /// shape this core does not emit.
    ///
    /// The decoder being a superset of the encoder is a property, and this is
    /// where it is stated as code rather than as a sentence in a doc comment.
    #[must_use]
    pub fn to_outgoing(&self) -> Option<Outgoing<'a>> {
        if self.reflection.is_some() {
            return None;
        }
        Some(Outgoing {
            id: self.id,
            status: self.status,
            options: self.options,
            target: self.target,
            global_id: self.global_id,
        })
    }
}

/// Why a frame could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The buffer holds fewer bytes than the frame has reached. `Short` is the
    /// only variant a caller can wait out; every other one means the frame lies.
    Short {
        /// How far into the frame the parser must get before it can decide.
        need: usize,
        /// Bytes the buffer holds.
        have: usize,
    },
    /// A metadata length below [`FIXED`] or above [`META_MAX`].
    MetaLen(u16),
    /// A status byte the format does not name.
    Status(u8),
    /// A network byte the format does not name.
    Network(u8),
    /// An address-family byte the format does not name.
    Family(u8),
    /// The metadata ended inside a field it had already promised.
    Truncated,
}

impl Error {
    /// [`Self::Short`] with its two counts.
    const fn short(need: usize, have: usize) -> Self {
        Self::Short { need, have }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { need, have } => write!(f, "short: {have} of {need} bytes"),
            Self::MetaLen(len) => write!(f, "meta length {len} is outside {FIXED}..={META_MAX}"),
            Self::Status(byte) => write!(f, "status {byte:#04x} is not a frame status"),
            Self::Network(byte) => write!(f, "network {byte:#04x} is not a transport"),
            Self::Family(byte) => write!(f, "address family {byte:#04x} is not one"),
            Self::Truncated => write!(f, "metadata ends inside a field it promised"),
        }
    }
}

impl std::error::Error for Error {}

/// Read one frame off the front of `buf`, with the bytes the frame occupies.
///
/// One pass, in place, borrowing the payload rather than copying it: the caller
/// gets a slice into the buffer it already had. Nothing here allocates, and
/// nothing here writes — including the metadata, which every implementation this
/// replaces first copies into a scratch buffer of its own.
pub fn decode(buf: &[u8], tail: NewTail) -> Result<(Incoming<'_>, usize), Error> {
    let Some((&head, after)) = buf.split_first_chunk::<2>() else {
        return Err(Error::short(2, buf.len()));
    };
    let declared = u16::from_be_bytes(head);
    if !(FIXED..=META_MAX).contains(&usize::from(declared)) {
        return Err(Error::MetaLen(declared));
    }
    let meta_len = usize::from(declared);
    let Some(meta) = after.get(..meta_len) else {
        return Err(Error::short(2 + meta_len, buf.len()));
    };

    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = Status::from_byte(meta[2]).ok_or(Error::Status(meta[2]))?;
    let options = meta[3];

    let mut at = FIXED;
    let mut target = None;
    // The status decides, except on `Keep`, where the one byte that could be a
    // network byte decides: `0x02` there is a datagram that brought its own
    // destination, and anything else is a frame with no address in it.
    let udp = meta.get(at) == Some(&Network::Udp.byte());
    if status == Status::New || (status == Status::Keep && udp) {
        let (found, used) = Target::take(&meta[at..])?;
        at += used;
        target = Some(found);
    }

    let mut global_id = None;
    let mut reflection = None;
    if status == Status::New {
        match tail {
            // A bridge's addresses and a NAT identity are the same field shapes,
            // so only the caller knows which to read; upstream reads one and
            // returns, which is the same decision with a flag in reach.
            NewTail::Reverse => reflection = read_reflection(&meta[at..])?,
            NewTail::Forward => {
                if options & DATA != 0
                    && target.is_some_and(|t| t.network == Network::Udp)
                    && meta.len() - at >= GLOBAL_ID
                {
                    let mut identity = [0u8; GLOBAL_ID];
                    identity.copy_from_slice(&meta[at..at + GLOBAL_ID]);
                    global_id = Some(identity);
                }
            }
        }
    }

    let mut consumed = 2 + meta_len;
    let mut data = None;
    if options & DATA != 0 {
        debug_assert!(
            buf.len() >= consumed,
            "the metadata slice was proven present"
        );
        let (&len, payload) = buf[consumed..]
            .split_first_chunk::<2>()
            .ok_or_else(|| Error::short(consumed + 2, buf.len()))?;
        let len = usize::from(u16::from_be_bytes(len));
        let body = payload
            .get(..len)
            .ok_or_else(|| Error::short(consumed + 2 + len, buf.len()))?;
        consumed += 2 + len;
        data = Some(body);
    }

    Ok((
        Incoming {
            id,
            status,
            options,
            target,
            global_id,
            reflection,
            data,
        },
        consumed,
    ))
}

/// The source and, when a third address follows, the local address.
///
/// A zero network byte is padding and ends the tail, which is the one rule that
/// lets a bridge say "no local address" without a flag.
///
/// `#[inline]` because it is the only thing `decode` does for a reverse-mux peer
/// beyond its first address, and gate 6 measured that shape at 0.91x with it
/// behind a call: an `Option<Reflection>` is about fifty bytes and comes back
/// through memory, so a call here is a call plus a copy of the whole tail.
#[inline]
fn read_reflection(rest: &[u8]) -> Result<Option<Reflection<'_>>, Error> {
    let Some((&network, _)) = rest.split_first() else {
        return Ok(None);
    };
    if network == 0 {
        return Ok(None);
    }
    let (source, used) = Target::take(rest)?;
    let local = match Target::take(&rest[used..]) {
        Ok((found, _)) => Some(found),
        // A zero network byte ends the tail, and a metadata that runs out means
        // the peer sent a source and nothing else. Any other refusal is a lie
        // and is reported as one.
        Err(Error::Network(0) | Error::Truncated) => None,
        Err(other) => return Err(other),
    };
    Ok(Some(Reflection { source, local }))
}

/// Why [`Ids::take`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The concurrency cap is reached, so another mux connection is the answer.
    Full,
    /// Every id in the sixteen-bit field is spent. Upstream's counter is a
    /// `u16` that wraps, and the wrap overwrites a live session with id zero;
    /// this refuses rather than doing that.
    Exhausted,
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("the session cap is reached"),
            Self::Exhausted => f.write_str("every session id is spent"),
        }
    }
}

impl std::error::Error for IdError {}

/// The session ids one mux connection hands out.
///
/// Monotonic from one, never reused, and never wrapped. The sixteen-bit field is
/// the format's, so 65535 ids is all there is; spending them is the answer, not
/// a wrap.
#[derive(Debug, Clone)]
pub struct Ids {
    next: u32,
    live: usize,
    cap: usize,
}

impl Ids {
    /// `cap` is the most sessions that may be live at once. Zero means the whole
    /// id field, which is what a caller asking for no ceiling is asking for;
    /// [`Sessions::with_cap`] reads a zero as one instead, because there the cap
    /// also sizes the table.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            next: 1,
            live: 0,
            cap,
        }
    }

    /// The next id, or why there is none.
    pub fn take(&mut self) -> Result<u16, IdError> {
        if self.cap != 0 && self.live >= self.cap {
            return Err(IdError::Full);
        }
        let id = u16::try_from(self.next).map_err(|_| IdError::Exhausted)?;
        self.next += 1;
        self.live += 1;
        Ok(id)
    }

    /// Give an id back once its session has closed.
    pub fn give_back(&mut self) {
        self.live = self.live.saturating_sub(1);
    }

    /// Sessions currently live, which is what the cap counts.
    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    /// Sessions ever opened on this connection, which is what the id space counts.
    #[must_use]
    pub const fn opened(&self) -> u32 {
        self.next - 1
    }

    /// The most sessions that may be live at once, zero being unlimited.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }
}

/// One slot of the session table.
///
/// The three shapes are what a linear probe needs: an untouched slot ends a
/// chain, a tombstone does not, and only [`Slot::Live`] holds anything.
#[derive(Debug)]
enum Slot<T> {
    /// Never used. A probe that reaches one of these stops here.
    Empty,
    /// A live session, under the id it was opened with.
    Live(u16, T),
    /// A session that closed. The id stays so a probe for it ends here rather
    /// than running off the end of a chain that leads past it.
    Closed(u16),
}

/// The sessions one mux connection is carrying.
///
/// Upstream keeps these in a hash map keyed by the session id, and the ids are
/// dense, monotonic and bounded by the concurrency cap — so the hash is a
/// function of a value that was handed out in order. This is the map that needs
/// no hash: a power-of-two table sized once from the cap, linear probing, and the
/// key compared as part of the probe. One allocation for the life of the
/// connection, no rehash, and a lookup is a mask and at most a few compares.
///
/// The id a peer sends is a **key, never an index**. That is the whole reason the
/// table is bounded by the cap rather than by the id space: nothing a peer can
/// choose makes this allocate, where an id-indexed array would grow to 65536
/// slots because of one frame.
#[derive(Debug)]
pub struct Sessions<T> {
    slots: Vec<Slot<T>>,
    mask: usize,
    live: usize,
    cap: usize,
}

impl<T> Sessions<T> {
    /// A table for [`DEFAULT_CAP`] live sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_CAP)
    }

    /// A table for `cap` live sessions, sized once from it and never grown.
    ///
    /// The array is twice `cap` rounded up to a power of two, which is what keeps
    /// a probe chain short and keeps a full table unreachable while the live cap
    /// is not reached — the tombstone count is bounded by it too, so a session
    /// that opens and closes forever cannot fill the table either. `cap` below
    /// one is read as one.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        let cap = cap.max(1);
        let len = cap.saturating_mul(2).max(4).next_power_of_two();
        // Built from an iterator rather than `vec![..; len]` because `Slot<T>` is
        // not `Clone` for an arbitrary `T`, and requiring one to open a table
        // would bound what a session may be.
        let slots = (0..len).map(|_| Slot::Empty).collect();
        Self {
            slots,
            mask: len - 1,
            live: 0,
            cap,
        }
    }

    /// The most sessions that may be live at once.
    #[must_use]
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Sessions currently live.
    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    /// Slots the table holds. Reported so a caller can see what the table costs
    /// before it costs it.
    #[must_use]
    pub const fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// The slot holding `id`, and the first slot on the way there that a new
    /// session could take.
    ///
    /// Both come out of one walk because the frame path has to pay for one: a
    /// probe that reaches an untouched slot has proved the id absent, and the
    /// first tombstone it passed is where a new session belongs so that no probe
    /// chain is broken behind it.
    fn probe(&self, id: u16) -> (Option<usize>, Option<usize>) {
        let mut at = self.mask & usize::from(id);
        let mut free = None;
        for _ in 0..=self.mask {
            match &self.slots[at] {
                Slot::Empty => {
                    if free.is_none() {
                        free = Some(at);
                    }
                    return (None, free);
                }
                Slot::Live(key, _) | Slot::Closed(key) if *key == id => return (Some(at), free),
                Slot::Live(..) | Slot::Closed(..) => {}
            }
            at = (at + 1) & self.mask;
        }
        (None, free)
    }

    /// Install `value` under `id`, handing back whatever it displaced.
    ///
    /// `None` when the live cap is reached. Upstream's server has no cap at all
    /// and allocates a session per `New` frame it accepts, and it never checks
    /// whether an id is already live — so a peer that reuses one silently
    /// orphans the stream behind it. Here the displaced session comes back to the
    /// caller, who has to decide what happens to it.
    pub fn open(&mut self, id: u16, value: T) -> Option<Option<T>> {
        let (found, free) = self.probe(id);
        if let Some(at) = found {
            // Replacing in place leaves the probe chain alone.
            let replaced = std::mem::replace(&mut self.slots[at], Slot::Live(id, value));
            return Some(if let Slot::Live(_, old) = replaced {
                Some(old)
            } else {
                self.live += 1;
                None
            });
        }
        if self.live >= self.cap {
            return None;
        }
        // The table is at least twice the cap and a slot is never removed, so
        // some slot is free whenever the cap is not reached: if every slot were
        // live there would be at least twice the cap of them.
        let at = free?;
        self.live += 1;
        self.slots[at] = Slot::Live(id, value);
        Some(None)
    }

    /// The session under `id`.
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&T> {
        let at = self.probe(id).0?;
        match &self.slots[at] {
            Slot::Live(_, value) => Some(value),
            Slot::Empty | Slot::Closed(_) => None,
        }
    }

    /// The session under `id`, mutably.
    pub fn get_mut(&mut self, id: u16) -> Option<&mut T> {
        let at = self.probe(id).0?;
        match &mut self.slots[at] {
            Slot::Live(_, value) => Some(value),
            Slot::Empty | Slot::Closed(_) => None,
        }
    }

    /// Take the session out from under `id`, closing it.
    ///
    /// The id stays in its slot as a tombstone, because removing it would break
    /// the probe chain of every id that hashed past it — the one thing a linear
    /// probe cannot repair after the fact.
    pub fn close(&mut self, id: u16) -> Option<T> {
        let at = self.probe(id).0?;
        match std::mem::replace(&mut self.slots[at], Slot::Closed(id)) {
            Slot::Live(_, value) => {
                self.live -= 1;
                Some(value)
            }
            _ => None,
        }
    }
}

impl<T> Default for Sessions<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: [u8; 2] = [0x00, 0x14];
    const ID: [u8; 2] = [0x00, 0x01];

    /// `New`, `TCP`, `example.com:80`, session 1, payload `abcd`, spelled out
    /// from the format table rather than from this encoder.
    ///
    /// Every byte, with what put it there:
    ///
    /// ```text
    /// 00 14 | 00 01 | 01 | 01 | 01 | 00 50 | 02 | 0b | "example.com" | 00 04 | "abcd"
    ///  ^^^^   ^^^^^^   ^^   ^^   ^^   ^^^^^^   ^^   ^^   ^^^^^^^^^^^   ^^^^^^   ^^^^^^
    ///  20     1       New  DATA TCP  80       dom  11   11 bytes      4       payload
    /// ```
    ///
    /// The 20 is the only number with any freedom in it, so it is the one worth
    /// doing out: two for the id, one for the status, one for the option, one for
    /// the network, two for the port, one for the family, one for the domain's
    /// length, and eleven for the domain itself — twenty. The payload's own
    /// length sits after the metadata and is counted by neither, which is the
    /// whole reason the frame can be read with one length in hand.
    ///
    /// The first eleven bytes stay escaped so the field boundaries are visible in
    /// the literal; the rest is the text it stands for.
    const NEW_DOMAIN: [u8; 28] =
        *b"\x00\x14\x00\x01\x01\x01\x01\x00\x50\x02\x0bexample.com\x00\x04abcd";

    #[test]
    fn a_new_frame_is_the_bytes_the_fields_add_up_to() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "example.com", 80)),
            global_id: None,
        };
        let mut buf = [0u8; 64];
        let n = out.encode_into(Some(b"abcd"), &mut buf);
        assert_eq!(&buf[..n], &NEW_DOMAIN);
        assert_eq!(
            n, 28,
            "two of length, twenty of metadata, two of chunk, four of payload"
        );
        assert_eq!(
            &buf[..2],
            &LEN,
            "the length counts the metadata and neither chunk nor itself"
        );
        assert_eq!(&buf[2..4], &ID);
        assert_eq!(out.meta_len(), 20);
        assert_eq!(out.frame_len(4), 28);
    }

    #[test]
    fn a_new_frame_decodes_back_into_what_encoded_it() {
        let (frame, used) = decode(&NEW_DOMAIN, NewTail::Forward).expect("it decodes");
        assert_eq!(used, NEW_DOMAIN.len(), "the whole frame, chunk included");
        assert_eq!(frame.id, 1);
        assert_eq!(frame.status, Status::New);
        assert_eq!(frame.options, DATA);
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Tcp, "example.com", 80))
        );
        assert_eq!(frame.global_id, None);
        assert_eq!(frame.reflection, None);
        assert_eq!(frame.data, Some(&b"abcd"[..]));
        let (again, _) = decode(&NEW_DOMAIN, NewTail::Forward).expect("and again");
        assert_eq!(frame, again, "decoding is a function of the bytes");
    }

    #[test]
    fn the_ipv4_and_ipv6_families_sit_where_the_field_says() {
        let v4 = Outgoing {
            id: 7,
            status: Status::New,
            options: 0,
            target: Some(Target::of(Network::Tcp, "192.0.2.53", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = v4.encode_into(None, &mut buf);
        // 2 length + 2 id + 1 status + 1 option + 1 network + 2 port + 1 family + 4.
        assert_eq!(v4.meta_len(), 12);
        assert_eq!(n, 14);
        assert_eq!(
            &buf[..n],
            &[0, 12, 0, 7, 1, 0, 1, 0x01, 0xbb, 1, 192, 0, 2, 53]
        );

        let v6 = Outgoing {
            id: 7,
            status: Status::New,
            options: 0,
            target: Some(Target::of(Network::Tcp, "2001:db8::1", 443)),
            global_id: None,
        };
        let n = v6.encode_into(None, &mut buf);
        assert_eq!(v6.meta_len(), 24, "four octets become sixteen");
        assert_eq!(n, 26);
        let frame = decode(&buf[..n], NewTail::Forward).expect("v6 decodes").0;
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Tcp, "2001:db8::1", 443))
        );
        assert_eq!(frame.data, None);
    }

    #[test]
    fn a_new_udp_frame_carries_eight_bytes_of_nat_identity() {
        let identity = [0xa1u8; GLOBAL_ID];
        let out = Outgoing {
            id: 3,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Udp, "example.com", 53)),
            global_id: Some(identity),
        };
        let mut buf = [0u8; 64];
        let n = out.encode_into(Some(b"q"), &mut buf);
        // 4 fixed + 3 network-and-port + 13 address + 8 identity, then a chunk.
        assert_eq!(out.meta_len(), 28);
        assert_eq!(n, 33);
        assert_eq!(&buf[2..4], &[0, 3]);
        assert_eq!(
            &buf[22..30],
            &identity,
            "the identity sits after the target address"
        );
        assert_eq!(
            &buf[30..n],
            &[0, 1, b'q'],
            "the chunk is length then payload"
        );

        let frame = decode(&buf[..n], NewTail::Forward)
            .expect("udp new decodes")
            .0;
        assert_eq!(frame.global_id, Some(identity));
        assert_eq!(frame.data, Some(&b"q"[..]));
    }

    #[test]
    fn keep_and_end_carry_only_the_four_fixed_bytes() {
        for status in [Status::Keep, Status::End, Status::KeepAlive] {
            let out = Outgoing::bare(9, status, 0);
            let mut buf = [0u8; 16];
            let n = out.encode_into(None, &mut buf);
            assert_eq!(n, 6, "{status:?}: two of length and four of metadata");
            assert_eq!(buf[..n], [0, 4, 0, 9, status.byte(), 0]);
            assert_eq!(out.meta_len(), 4);
            let frame = decode(&buf[..n], NewTail::Forward).expect("decodes");
            assert_eq!(frame.0.status, status);
            assert_eq!(frame.0.target, None);
            assert_eq!(frame.0.data, None);
        }
    }

    #[test]
    fn an_end_frame_says_why_with_one_bit() {
        let out = Outgoing::bare(4, Status::End, ERROR);
        let mut buf = [0u8; 16];
        let n = out.encode_into(None, &mut buf);
        assert_eq!(buf[5], ERROR);
        assert_eq!(
            decode(&buf[..n], NewTail::Forward)
                .expect("decodes")
                .0
                .options,
            ERROR
        );
    }

    #[test]
    fn a_keep_frame_may_bring_its_own_datagram_destination() {
        // Byte four is the only signal: 0x02 means a datagram carried its own
        // destination, anything else means the frame has no address in it.
        let out = Outgoing {
            id: 2,
            status: Status::Keep,
            options: DATA,
            target: Some(Target::of(Network::Udp, "192.0.2.9", 5353)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(b"ping"), &mut buf);
        assert_eq!(
            buf[6], 0x02,
            "the network byte is what marks this as a datagram"
        );
        let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
        assert_eq!(
            frame.target,
            Some(Target::of(Network::Udp, "192.0.2.9", 5353))
        );
        assert_eq!(frame.data, Some(&b"ping"[..]));

        // The same status with no target reads as a frame with no address.
        let bare = Outgoing::bare(2, Status::Keep, DATA);
        let n = bare.encode_into(Some(b"hi"), &mut buf);
        let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
        assert_eq!(frame.target, None, "no network byte, no address");
        assert_eq!(frame.data, Some(&b"hi"[..]));
    }

    #[test]
    fn a_reverse_mux_frame_is_read_but_never_written() {
        // A target, then a source, then a local: three addresses in one frame,
        // which is the shape upstream's own writer produces and its own reader
        // refuses above 512 bytes of metadata.
        let mut addresses = [0u8; 64];
        let mut at = 0;
        for (network, port, host) in [
            (Network::Udp, 53u16, "example.com"),
            (Network::Tcp, 443, "192.0.2.1"),
            (Network::Tcp, 8443, "198.51.100.7"),
        ] {
            addresses[at] = network.byte();
            at += 1;
            addresses[at..at + 2].copy_from_slice(&port.to_be_bytes());
            at += 2;
            at += Addr::of(host).encode_into(&mut addresses[at..]);
        }
        let mut buf = [0u8; 64];
        buf[..2].copy_from_slice(&((4 + at) as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0x00, 0x05]);
        buf[4] = Status::New.byte();
        buf[6..6 + at].copy_from_slice(&addresses[..at]);
        let total = 6 + at;

        let frame = decode(&buf[..total], NewTail::Reverse)
            .expect("a bridge's frame is framed, not dropped")
            .0;
        assert_eq!(frame.id, 5);
        let reflection = frame.reflection.expect("the tail is reflection");
        assert_eq!(
            reflection.source,
            Target::of(Network::Tcp, "192.0.2.1", 443)
        );
        assert_eq!(
            reflection.local,
            Some(Target::of(Network::Tcp, "198.51.100.7", 8443))
        );
        assert_eq!(
            frame.to_outgoing(),
            None,
            "which is why it is not written back"
        );
    }

    #[test]
    fn a_zero_network_byte_ends_a_reflection() {
        // A `New` frame always names its own destination first; the bridge's
        // source and local follow, and a zero network byte in that position is
        // how a bridge says "no local address" without a flag.
        let target = Target::of(Network::Tcp, "192.0.2.53", 443);
        let source = Target::of(Network::Tcp, "192.0.2.1", 443);
        let mut tail = [0u8; 64];
        let mut at = 0;
        at += target.encode_into(&mut tail[at..]);
        at += source.encode_into(&mut tail[at..]);
        tail[at] = 0;

        let mut buf = [0u8; 64];
        buf[..2].copy_from_slice(&((4 + at + 1) as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0, 1]);
        buf[4] = Status::New.byte();
        let tail_len = at + 1;
        buf[6..6 + tail_len].copy_from_slice(&tail[..tail_len]);
        let total = 7 + at;

        let frame = decode(&buf[..total], NewTail::Reverse).expect("decodes").0;
        assert_eq!(frame.target, Some(target));
        let reflection = frame.reflection.expect("a source is enough");
        assert_eq!(reflection.source, source);
        assert_eq!(
            reflection.local, None,
            "zero means no local address, not a broken one"
        );
    }

    #[test]
    fn every_domain_length_survives_a_round_trip() {
        // Dense over the length byte: 0 through 255, every one of them a
        // different frame length and a different position for the chunk.
        for len in 0..=addr::MAX_DOMAIN {
            let host = "d".repeat(len);
            let out = Outgoing {
                id: u16::MAX - len as u16,
                status: Status::New,
                options: DATA,
                target: Some(Target::of(Network::Tcp, &host, len as u16)),
                global_id: None,
            };
            let payload = [0x5au8; 3];
            let mut buf = vec![0u8; out.frame_len(payload.len())];
            let n = out.encode_into(Some(&payload), &mut buf);
            assert_eq!(
                n,
                buf.len(),
                "len {len}: the frame is exactly as long as it said"
            );
            let (frame, used) =
                decode(&buf, NewTail::Forward).unwrap_or_else(|e| panic!("len {len}: {e}"));
            assert_eq!(used, n, "len {len}");
            assert_eq!(frame.id, u16::MAX - len as u16, "len {len}");
            assert_eq!(frame.data, Some(&payload[..]), "len {len}");
            let target = frame.target.expect("a new frame names its target");
            assert_eq!(target.port, len as u16, "len {len}");
            assert_eq!(target.addr.body(), host.as_bytes(), "len {len}");
        }
    }

    #[test]
    fn a_zero_length_payload_is_a_frame_and_not_an_error() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(&[]), &mut buf);
        assert_eq!(&buf[n - 2..n], &[0, 0], "an empty chunk is two zero bytes");
        assert_eq!(
            decode(&buf[..n], NewTail::Forward).expect("decodes").0.data,
            Some(&[][..])
        );
    }

    #[test]
    fn trailing_bytes_are_the_next_frames_and_not_ours() {
        let mut buf = [0u8; 64];
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let n = out.encode_into(Some(b"one"), &mut buf);
        buf[n] = 0xde;
        buf[n + 1] = 0xad;
        let (frame, used) = decode(&buf[..n + 2], NewTail::Forward).expect("decodes");
        assert_eq!(used, n, "one frame is one frame");
        assert_eq!(frame.data, Some(&b"one"[..]));
    }

    #[test]
    fn the_decoder_refuses_only_what_it_cannot_frame() {
        // Every case is a whole frame: two bytes of length and the metadata that
        // length promises, so the only thing being refused is the metadata.
        let cases: [(&[u8], Error, &str); 7] = [
            (&[], Error::Short { need: 2, have: 0 }, "no length"),
            (&[0], Error::Short { need: 2, have: 1 }, "half a length"),
            (
                &[0, 3, 0, 1, 1, 0],
                Error::MetaLen(3),
                "shorter than the fixed four",
            ),
            (
                &[0, 200, 0, 1],
                Error::Short { need: 202, have: 4 },
                "a length the buffer has not caught up to",
            ),
            (
                &[0, 4, 0, 1, 9, 0],
                Error::Status(9),
                "a status nobody names",
            ),
            (
                &[0, 9, 0, 1, 1, 0, 5, 0, 80, 1, 192],
                Error::Network(5),
                "a transport nobody names",
            ),
            (
                &[0, 9, 0, 1, 1, 0, 1, 0, 80, 9, 192],
                Error::Family(9),
                "an address family nobody names",
            ),
        ];
        for (input, want, why) in cases {
            assert_eq!(decode(input, NewTail::Forward), Err(want), "{why}");
        }
    }

    #[test]
    fn metadata_that_ends_inside_a_field_is_refused_not_guessed() {
        // A New frame promising no room for a network, a port and a family says
        // so rather than reading whatever is nearest.
        assert_eq!(
            decode(&[0, 4, 0, 1, 1, 0], NewTail::Forward),
            Err(Error::Truncated),
            "not even a network byte"
        );
        assert_eq!(
            decode(&[0, 8, 0, 1, 1, 0, 1, 0, 80, 1], NewTail::Forward),
            Err(Error::Truncated),
            "a network and a port but no address"
        );
    }

    #[test]
    fn a_frame_that_claims_more_than_the_format_holds_is_refused() {
        let over = (META_MAX + 1) as u16;
        assert_eq!(
            decode(&over.to_be_bytes(), NewTail::Forward),
            Err(Error::MetaLen(over)),
            "781 is the whole format's ceiling and 782 is not"
        );
        // The ceiling itself is accepted, which is the interop half: a peer
        // sending what upstream's writer can produce is framed rather than
        // disconnected by a reader that stops at 512.
        let mut buf = vec![0u8; 2 + META_MAX];
        buf[..2].copy_from_slice(&(META_MAX as u16).to_be_bytes());
        buf[2..4].copy_from_slice(&[0, 1]);
        buf[4] = Status::New.byte();
        buf[6] = Network::Tcp.byte();
        buf[7..9].copy_from_slice(&443u16.to_be_bytes());
        buf[9] = crate::addr::IPV4;
        buf[10..14].copy_from_slice(&[192, 0, 2, 1]);
        let frame = decode(&buf, NewTail::Forward).expect("781 is accepted");
        assert_eq!(frame.1, 2 + META_MAX);
        assert_eq!(
            frame.0.target,
            Some(Target::of(Network::Tcp, "192.0.2.1", 443))
        );
        assert_eq!(
            frame.0.global_id, None,
            "options are clear, so no identity is read"
        );
    }

    #[test]
    fn a_payload_the_buffer_has_not_caught_up_to_is_short_not_wrong() {
        let out = Outgoing {
            id: 1,
            status: Status::New,
            options: DATA,
            target: Some(Target::of(Network::Tcp, "192.0.2.1", 443)),
            global_id: None,
        };
        let mut buf = [0u8; 32];
        let n = out.encode_into(Some(b"abcdefgh"), &mut buf);
        assert_eq!(
            decode(&buf[..n - 1], NewTail::Forward),
            Err(Error::Short {
                need: n,
                have: n - 1
            })
        );
    }

    #[test]
    fn the_decoder_reads_a_superset_of_what_the_encoder_writes() {
        // Every frame the encoder can produce reads back to itself, and the one
        // shape it cannot produce is the only one that has no outgoing form.
        for len in [0usize, 1, 7, 63, 255] {
            let host = "h".repeat(len);
            for options in [0u8, DATA, DATA | ERROR] {
                let payload: Option<&[u8]> = if options & DATA != 0 {
                    Some(b"payload")
                } else {
                    None
                };
                let out = Outgoing {
                    id: 42,
                    status: Status::New,
                    options,
                    target: Some(Target::of(Network::Tcp, &host, 8080)),
                    global_id: None,
                };
                let mut buf = vec![0u8; out.frame_len(payload.map_or(0, <[u8]>::len))];
                let n = out.encode_into(payload, &mut buf);
                let frame = decode(&buf[..n], NewTail::Forward).expect("decodes").0;
                let label = format!("len {len} options {options:#04x}");
                assert_eq!(frame.to_outgoing(), Some(out), "{label}");
                assert_eq!(frame.data, payload, "{label}");
            }
        }
    }

    #[test]
    fn ids_are_handed_out_once_each_and_refused_rather_than_wrapped() {
        let mut ids = Ids::new(0);
        assert_eq!(
            ids.take(),
            Ok(1),
            "the first id is one, as upstream's pre-increment makes it"
        );
        assert_eq!(ids.take(), Ok(2));
        assert_eq!(ids.live(), 2);
        assert_eq!(ids.opened(), 2);
        ids.give_back();
        assert_eq!(ids.live(), 1);
        assert_eq!(ids.take(), Ok(3), "a returned id is not reissued");

        let mut capped = Ids::new(2);
        assert_eq!(capped.take(), Ok(1));
        assert_eq!(capped.take(), Ok(2));
        assert_eq!(
            capped.take(),
            Err(IdError::Full),
            "another connection is the answer here"
        );
        assert_eq!(capped.live(), 2);
        assert_eq!(capped.cap(), 2);
        capped.give_back();
        assert_eq!(capped.take(), Ok(3), "and the id space moves on regardless");

        // Upstream's counter is a u16 and wraps: the 65536th session overwrites a
        // live one with id 0. This stops at the end of the field instead.
        let mut all = Ids::new(0);
        for expected in 1..=u32::from(u16::MAX) {
            assert_eq!(all.take(), Ok(expected as u16), "session {expected}");
        }
        assert_eq!(all.take(), Err(IdError::Exhausted));
        assert_eq!(all.opened(), u32::from(u16::MAX));
    }

    #[test]
    fn sessions_are_indexed_by_id_and_handed_back_on_close() {
        let mut sessions = Sessions::new();
        assert_eq!(sessions.cap(), DEFAULT_CAP);
        assert_eq!(sessions.open(1, "one"), Some(None));
        assert_eq!(sessions.open(3, "three"), Some(None));
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.get(1), Some(&"one"));
        assert_eq!(sessions.get(2), None);
        assert_eq!(sessions.close(1), Some("one"));
        assert_eq!(sessions.live(), 1);
        assert_eq!(sessions.get(1), None);
        if let Some(slot) = sessions.get_mut(3) {
            *slot = "THREE";
        }
        assert_eq!(sessions.get(3), Some(&"THREE"));
        assert_eq!(sessions.close(1), None, "a tombstone is not a session");
        assert_eq!(sessions.live(), 1, "and closing one does not count twice");
    }

    #[test]
    fn reopening_a_live_id_hands_the_old_session_back() {
        // Upstream writes the new one over the old and the stream behind it is
        // gone with nobody told. Here it comes back.
        let mut sessions = Sessions::with_cap(8);
        assert_eq!(sessions.open(4, "first"), Some(None));
        assert_eq!(sessions.open(4, "second"), Some(Some("first")));
        assert_eq!(sessions.live(), 1, "one session, not two");
        assert_eq!(sessions.get(4), Some(&"second"));
    }

    #[test]
    fn an_id_a_peer_invents_costs_a_slot_it_already_paid_for() {
        // The id is a key, never an index, so the largest one in the field opens
        // like any other and the table does not grow for it. An id-indexed array
        // would have to grow to 65536 entries because of this one frame.
        let mut sessions = Sessions::<u32>::with_cap(2);
        assert_eq!(sessions.slot_count(), 4, "twice the cap, a power of two");
        assert_eq!(sessions.open(u16::MAX, 1), Some(None));
        assert_eq!(sessions.slot_count(), 4, "no growth, whatever the id");
        assert_eq!(sessions.get(u16::MAX), Some(&1));
        assert_eq!(sessions.live(), 1);
        assert_eq!(sessions.open(0, 2), Some(None));
        assert_eq!(sessions.get(0), Some(&2));
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.open(7, 3), None, "the cap is two, not three");
    }

    #[test]
    fn a_closed_slot_is_reused_rather_than_left_to_pile_up() {
        // A session that opens and closes forever must not fill the table: the
        // tombstone a close leaves is where the next session goes, which is what
        // keeps the slot count the same thing for a long-lived connection.
        let mut sessions = Sessions::<u32>::with_cap(2);
        let slots = sessions.slot_count();
        for round in 0..1_000u32 {
            let id = u16::try_from(round % 2).expect("two ids");
            assert_eq!(sessions.open(id, round), Some(None), "round {round}");
            assert_eq!(sessions.close(id), Some(round), "round {round}");
            assert_eq!(sessions.live(), 0, "round {round}");
        }
        assert_eq!(sessions.slot_count(), slots, "1000 rounds and no growth");
    }

    #[test]
    fn the_concurrency_cap_counts_live_sessions_and_not_the_ids_used() {
        let mut sessions = Sessions::with_cap(2);
        assert_eq!(sessions.open(1, 'a'), Some(None));
        assert_eq!(sessions.open(2, 'b'), Some(None));
        assert_eq!(
            sessions.open(3, 'c'),
            None,
            "a third is over the cap whatever its id"
        );
        assert_eq!(sessions.close(2), Some('b'));
        assert_eq!(
            sessions.open(u16::MAX, 'z'),
            Some(None),
            "the id is a key, so a big one opens like a small one"
        );
        assert_eq!(sessions.live(), 2);
        assert_eq!(sessions.open(9, 'c'), None, "and the cap still counts");
        assert_eq!(sessions.close(u16::MAX), Some('z'));
        assert_eq!(
            sessions.open(9, 'c'),
            Some(None),
            "the freed slot takes a small id"
        );
    }
}
