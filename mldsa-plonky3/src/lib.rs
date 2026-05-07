//! Plonky3 STARK experiments for **ML-DSA-44** (FIPS 204, ex-Dilithium2).
//!
//! The upstream implementation lives in [`third_party/ml-dsa`](../third_party/ml-dsa) (RustCrypto),
//! with small helpers for witness extraction.
//!
//! ## Current AIR (bootstrap)
//!
//! [`MlDsa44ChallengeBytesAir`] checks **byte-wise equality** between:
//! - the challenge prefix `c_tilde` in the signature ([`ml_dsa::Signature::c_tilde`]), and  
//! - the value from [`ml_dsa::VerifyingKey::recomputed_challenge_bytes`],
//!
//! over **32 bytes** (ML-DSA-44 `Lambda`), one byte per trace row.
//!
//! **Not in-circuit yet:** Shake256, `sample_in_ball`, NTT matrix multiply, `use_hint`, `encode_w1`.
//! Those steps run in native Rust (via `ml-dsa`); the proof only binds the **final challenge comparison**
//! once honest witnesses are supplied. Next milestones are incremental gadgets (hash, then NTT layer).

pub mod air;
pub mod config;
pub mod witness;

pub use air::{MlDsa44ChallengeBytesAir, MLDSA44_LAMBDA_BYTES};
pub use config::stark_config_poseidon2;
pub use witness::{build_ml_dsa44_challenge_trace, challenge_air};
