//! Falcon signature verification expressed as a [Plonky3](https://github.com/Plonky3/Plonky3) STARK AIR.
//!
//! See **[`README.md`](./README.md)** for trace layout, **To tighten** (message hash / public binding),
//! field sizes, and a numeric `quot_*` example.
//!
//! The [`FalconDualNttEquationAir`] enforces, per NTT index:
//! - `prod_sig_pos_pk = sig_pos_ntt * pk_ntt` and `prod_sig_neg_pk = sig_neg_ntt * pk_ntt` in KoalaBear
//!   (sound because true products are $< q^2$ and below the KoalaBear prime),
//! - `hm + v_neg + prod_sig_neg_pk = lhs_mod + quot_l * MODULUS` and the symmetric right side,
//!   with `quot_l`, `quot_r` given as **14-bit** bit-decompositions,
//! - `lhs_mod == rhs_mod`.
//!
//! Still **not** proved: NTT consistency for `sig`/`v`, coefficient-domain dual feasibility
//! (`pos * neg = 0`), or Falcon norm / range bounds (see `falcon-r1cs` / `falcon-plonk`).

pub mod air;
pub mod config;
pub mod witness;

pub use air::FalconDualNttEquationAir;
pub use config::stark_config_poseidon2;
pub use witness::build_falcon_dual_ntt_instance;
