#![deny(missing_debug_implementations)]

pub mod addr;
pub mod aead;
pub mod aesgcm;
pub mod b64;
pub(crate) mod chacha;
pub mod core;
pub mod failure;
pub mod foxy;
pub mod kcp;
pub mod mux;
pub mod policy;
pub mod poly1305;
pub mod record;
pub mod shadowsocks;
pub mod tls;
pub mod transport;
pub mod vless;

#[cfg(any(test, feature = "bench-reference"))]
pub mod reference {
    pub use crate::core::{backend, reference_xor};
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}

pub const fn chacha_backend() -> &'static str {
    crate::chacha::backend()
}
