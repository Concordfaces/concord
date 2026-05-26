//! S3-backed [`concord_core::store::Store`] for Concordfaces.
//!
//! Talks SigV4 to a path-style S3 gateway (CloudVerve in production, any
//! S3-compatible backend in test). The CLI wires this in behind the
//! `Store` trait so the rest of `push` / `pull` is store-agnostic.

#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod client;
pub mod sigv4;

pub use client::{S3Config, S3Error, S3Store};
pub use sigv4::Credentials;
