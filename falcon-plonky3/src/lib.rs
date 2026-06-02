//! Falcon signature verification expressed as a [Plonky3](https://github.com/Plonky3/Plonky3) STARK AIR.
//!
//! See **[`README.md`](./README.md)** for trace layout, the **verifier-facing statement**
//! (what STARKs bind vs what the verifier assumes from Rust),
//! remaining gaps vs a full verifier,
//! field sizes, why **`falcon-r1cs`’s deferred-reduction NTT** does not port to KoalaBear
//! (numeric examples + diagram), and a numeric `quot_*` example.
//!
//! The [`FalconDualNttEquationAir`] enforces, per NTT index:
//! - public periodic **`pk_ntt`**, **`hm_ntt`** (see [`air::dual_ntt_equation`](crate::air::dual_ntt_equation)),
//! - **preprocessed** reference NTT limbs for `sig_pos`, `sig_neg`, `v_pos`, `v_neg` equal to the main trace’s first four columns,
//! - `prod_sig_pos_pk = sig_pos_ntt * pk_ntt` and `prod_sig_neg_pk = sig_neg_ntt * pk_ntt` in KoalaBear
//!   (sound because true products are $< q^2$ and below the KoalaBear prime),
//! - `hm + v_neg + prod_sig_neg_pk = lhs_mod + quot_l * MODULUS` and the symmetric right side,
//!   with `quot_l`, `quot_r` given as **14-bit** bit-decompositions,
//! - `lhs_mod == rhs_mod`.
//!
//! Coefficient-domain **dual limb disjointness** is proved separately by
//! [`FalconCoeffDualProductZeroAir`] ([`build_falcon_coeff_dual_product_zero_instance`]); bit
//! reconstructions are **equal** to preprocessed expected `sig_pos`, `sig_neg` coefficients.
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
//! Optional **single-STARK** stack for benchmarking: [`prove_falcon_parsed_verify_single_stark`] /
//! [`verify_falcon_parsed_verify_single_stark`].
//!
//! **L² bound:** [`FalconL2BoundAir`] + [`build_falcon_l2_bound_trace`] (see [`full_verify`] bundle).
//!
//! The default parsed-verify bundle uses **seven** independent Fiat–Shamir transcripts (dual NTT,
//! coeff dual-zero, four [`FalconNttFullAir`](src/air/ntt_full.rs) proofs, L²). The experimental
//! [`FalconUnifiedParsedVerifyAir`](crate::air::unified_parsed_verify::FalconUnifiedParsedVerifyAir)
//! merges those constraints into one trace with segment selectors (still constrained against verifier-rebuilt
//! preprocessed / periodic data).

pub mod air;
pub mod config;
pub mod credential;
pub mod full_verify;
pub mod hash;
pub mod witness;

pub use air::{
    butterfly_j_jht_s, state_through_ntt_layer, FalconCoeffDualProductZeroAir,
    FalconDualNttEquationAir, FalconL2BoundAir, FalconNttLayer0Air, FalconNttLayerAir,
    FalconUnifiedParsedVerifyAir, StatementBoundAir, NTT_LAYER_MAIN_COLS,
    NUM_DUAL_NTT_PREPROCESSED_COLS, unified_trace_height,
};
pub use config::stark_config_poseidon2;
pub use witness::{
    build_falcon_coeff_dual_product_zero_instance,
    build_falcon_coeff_dual_product_zero_preprocessed,
    build_falcon_coeff_dual_product_zero_trace, build_falcon_dual_ntt_instance,
    build_falcon_l2_bound_preprocessed, build_falcon_l2_bound_trace,
    build_falcon_unified_parsed_verify_air,
    build_falcon_unified_parsed_verify_instance, build_ntt_layer0_trace, build_ntt_layer_instance,
    build_ntt_layer_main_trace,
};
pub use credential::{
    prove_credential, verify_credential, FalconCredentialProof, FalconCredentialPublicInputs,
    FalconCredentialVerifyKeys,
};
pub use full_verify::{
    falcon_statement_digest, prove_falcon_ntt_layers_only, prove_falcon_parsed_verify,
    prove_falcon_parsed_verify_single_stark, verify_falcon_parsed_verify,
    verify_falcon_parsed_verify_single_stark, verify_falcon_parsed_verify_with_breakdown,
    FalconParsedVerifyVerifierBreakdown, FalconVerifyStarkBundle, FALCON_STATEMENT_DIGEST_LEN,
};
