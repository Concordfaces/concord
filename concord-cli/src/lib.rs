//! Library surface of `concord-cli`. Exposes the push/pull primitives so
//! integration tests can drive them against a [`concord_core::store::MemoryStore`]
//! without spinning up a real S3 backend.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod cdn;
pub mod fmt;
pub mod key;
pub mod limiter;
pub mod pull;
pub mod push;
pub mod resume;
