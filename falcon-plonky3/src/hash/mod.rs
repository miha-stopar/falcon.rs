//! Falcon SHAKE256 hash-to-point (message + nonce → `hm` polynomial).
//!
//! Phase C: sponge linkage ([`shake_sponge`]) + Keccak-f STARK ([`p3_keccak_air`]) + rejection
//! sampling ([`hash_to_point`]).

mod prove_keccak;
mod shake;
pub mod witness;

pub use prove_keccak::prove_shake_keccak;
pub use shake::{hash_to_point, HashToPointResult, SHAKE_SQUEEZE_LEN};
