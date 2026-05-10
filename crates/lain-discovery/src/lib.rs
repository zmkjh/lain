#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod invite;
pub mod mdns;

pub use invite::InviteCode;
pub use mdns::MdnsDiscovery;
