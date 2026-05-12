//! Falcon signature verification expressed as a [Plonky3](https://github.com/Plonky3/Plonky3) STARK AIR.
//!
//! See **[`README.md`](./README.md)** for trace layout, remaining gaps vs a full verifier,
//! field sizes, why **`falcon-r1cs`’s deferred-reduction NTT** does not port to KoalaBear
//! (numeric examples + diagram), and a numeric `quot_*` example.
//!
//! The [`FalconDualNttEquationAir`] enforces, per NTT index:
//! - public periodic **`pk_ntt`**, **`hm_ntt`** (see [`air::dual_ntt_equation`](crate::air::dual_ntt_equation)),
//! - `prod_sig_pos_pk = sig_pos_ntt * pk_ntt` and `prod_sig_neg_pk = sig_neg_ntt * pk_ntt` in KoalaBear
//!   (sound because true products are $< q^2$ and below the KoalaBear prime),
//! - `hm + v_neg + prod_sig_neg_pk = lhs_mod + quot_l * MODULUS` and the symmetric right side,
//!   with `quot_l`, `quot_r` given as **14-bit** bit-decompositions,
//! - `lhs_mod == rhs_mod`.
//!
//! Coefficient-domain **dual limb disjointness** is proved separately by
//! [`FalconCoeffDualProductZeroAir`] ([`build_falcon_coeff_dual_product_zero_trace`]).
//!
//! **NTT (per layer):** [`FalconNttLayerAir`] with [`build_ntt_layer_instance`] proves **one**
//! Cooley–Tukey layer at a time (`layer ∈ [0, LOG_N)`), with a **preprocessed twiddle** column;
//! [`build_ntt_layer0_trace`] / [`FalconNttLayerAir::new_for_layer0`] remain shorthands for `layer = 0`.
//!
//! **Full NTT:** [`air::FalconNttFullAir`] chains all layers in one STARK (see [`full_verify`]).
//!
//! End-to-end parsed verification (dual NTT + coeff dual-zero + four full NTTs, with native L²):
//! [`prove_falcon_parsed_verify`] / [`verify_falcon_parsed_verify`] in [`full_verify`].
//!
//! **L² bound:** [`FalconL2BoundAir`] + [`build_falcon_l2_bound_trace`] (see [`full_verify`] bundle).
//!
//! Still **not** a single unified AIR like `falcon-r1cs` (cross-linking NTT outputs into the dual-NTT columns).

pub mod air;
pub mod config;
pub mod full_verify;
pub mod witness;

pub use air::{
    butterfly_j_jht_s, state_through_ntt_layer, FalconCoeffDualProductZeroAir,
    FalconDualNttEquationAir, FalconL2BoundAir, FalconNttLayer0Air, FalconNttLayerAir,
    NTT_LAYER_MAIN_COLS,
};
pub use config::stark_config_poseidon2;
pub use witness::{
    build_falcon_coeff_dual_product_zero_trace, build_falcon_dual_ntt_instance,
    build_falcon_l2_bound_trace, build_ntt_layer0_trace, build_ntt_layer_instance,
    build_ntt_layer_main_trace,
};
pub use full_verify::{
    prove_falcon_ntt_layers_only, prove_falcon_parsed_verify, verify_falcon_parsed_verify,
    FalconVerifyStarkBundle,
};
