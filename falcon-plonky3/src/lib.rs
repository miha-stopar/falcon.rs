//! Falcon signature verification expressed as a [Plonky3](https://github.com/Plonky3/Plonky3) STARK AIR.
//!
//! Current scope (branch `plonky3-port`):
//! - Preprocessed trace: `pk_ntt`, `hm_ntt` per coefficient (for future binding to public inputs).
//! - Main trace: dual NTT limbs for `sig` and `v`, plus `lhs_mod` / `rhs_mod` witnessing the
//!   per-index congruence from the `falcon-r1cs` `FalconDualNTTVerificationCircuit`:
//!   `(hm + v_neg + sig_neg * pk) ≡ (v_pos + sig_pos * pk) (mod MODULUS)` after full integer sums.
//! - The AIR only checks `lhs_mod == rhs_mod`. It does **not** yet prove that those columns are
//!   derived from `sig`, `pk`, `hm`, `v`, prove coefficient-domain `pos * neg = 0`, NTT layers,
//!   or the L2 / range machinery from the full R1CS circuit.

pub mod air;
pub mod config;
pub mod witness;

pub use air::FalconDualNttEquationAir;
pub use config::stark_config_poseidon2;
pub use witness::build_falcon_dual_ntt_instance;
