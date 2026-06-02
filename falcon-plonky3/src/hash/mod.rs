//! Falcon SHAKE256 hash-to-point (message + nonce → `hm` polynomial).
//!
//! Phase C: sponge linkage ([`shake_sponge`]) + Keccak-f STARK ([`p3_keccak_air`]) + rejection
//! sampling ([`hash_to_point`]).

mod prove_keccak;
mod shake;
pub mod witness;

pub use prove_keccak::{prove_shake_keccak, prove_shake_keccak_zk};
pub use shake::{
    compute_squeeze_byte_refs, hash_to_point, rate_byte, verify_squeeze_provenance,
    HashToPointResult, SqueezeByteRef,
    SHAKE_SQUEEZE_LEN,
};
