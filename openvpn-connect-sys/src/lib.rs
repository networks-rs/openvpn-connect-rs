//! Raw C ABI for the source-built OpenVPN 3 Core client.
//!
//! Prefer the safe `openvpn-connect` crate unless implementing another wrapper.

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::doc_markdown
)]

// Keep Cargo's native link metadata for the source-built static dependencies
// in the final link whenever `vendor` is enabled. The C++ adapter itself uses
// these libraries, while this raw Rust module does not call their Rust FFI.
#[cfg(feature = "vendor")]
use lz4_sys as _;
#[cfg(feature = "vendor")]
use openssl_sys as _;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
