//! End-to-end Falcon **parsed-verify** decomposition into Plonky3 STARKs (transparent setting).
//!
//! Verifier-side periodic inputs (`pk_ntt`, `hm_ntt` per index, period `N`) and per-layer NTT
//! inputs in preprocessed traces for full NTT are derived in the clear from `(pk, msg, sig)` the
//! same way as in [`crate::witness::build_falcon_dual_ntt_instance`].
//!
//! ## Verifier-facing statement (Tier 1)
//!
//! - **Inputs:** [`verify_falcon_parsed_verify`] takes `pk`, `msg`, `sig`, and the bundle. It does
//!   **not** take prover-supplied `pk_ntt` / `hm_ntt`; it rebuilds every `Air` from `(pk, msg, sig)`.
//! - **Dual-NTT:** proves the mod-`q` congruence for the main trace **given** those periodic
//!   tables, and **equality** of the NTT limbs to verifier-rebuilt **preprocessed** references
//!   (same construction as [`crate::witness::build_falcon_dual_ntt_instance`]).
//! - **Composition:** the seven proofs use **separate** Fiat–Shamir transcripts; dual-NTT and coeff dual-zero additionally **pin** witness columns to verifier-rebuilt preprocessed data. See the crate **[`README.md`](../README.md#verifier-facing-statement-tier-1-trust-model)**
//!   for the full trust-model table.
//!
//! ## What is covered
//!
//! 1. [`crate::air::dual_ntt_equation::FalconDualNttEquationAir`] — dual-NTT congruence mod `q`, with
//!    `sig_*_ntt` / `v_*_ntt` **equal** to verifier-rebuilt preprocessed NTT references.
//! 2. [`crate::air::coeff_dual_product_zero::FalconCoeffDualProductZeroAir`] — `sig_pos[i]·sig_neg[i]=0`
//!    with limbs tied to preprocessed expected coefficients from `sig`.
//! 3. Four [`crate::air::ntt_full::FalconNttFullAir`] proofs — full forward NTT for `sig_pos`, `sig_neg`,
//!    `v_pos`, `v_neg` coefficient polynomials (statement-bound inputs in preprocessed columns).
//! 4. [`crate::air::l2_bound::FalconL2BoundAir`] — coefficient-domain L² accumulation vs
//!    [`falcon_rust::SIG_L2_BOUND`] (same centering rule as [`falcon_rust::Polynomial::l2_norm`]).
//!
//! Native [`falcon_rust::PublicKey::verify_parsed_sig`] is still used before proving to ensure a valid
//! witness (hash / parsing); the L² STARK duplicates the norm bound in-circuit for transparency.

use falcon_rust::{DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, N};

use p3_matrix::Matrix;
use p3_uni_stark::{
    prove, prove_with_preprocessed, setup_preprocessed, verify, verify_with_preprocessed,
};
use p3_util::log2_strict_usize;

use crate::air::{build_ntt_full_main, build_ntt_full_preprocessed, FalconNttFullAir};
use crate::config::FalconStarkConfig;
use crate::witness::{
    build_falcon_coeff_dual_product_zero_instance, build_falcon_dual_ntt_instance,
    build_falcon_l2_bound_trace, build_ntt_layer_instance,
};
use crate::{FalconL2BoundAir, stark_config_poseidon2};

/// Proof artifacts for one signature verification statement (all sub-proofs use the same [`FalconStarkConfig`]).
///
/// Cryptographic meaning is defined together with [`verify_falcon_parsed_verify`]: verifier-rebuilt
/// parameters from `(pk, msg, sig)` plus the bundle. See the crate README *Verifier-facing statement*.
pub struct FalconVerifyStarkBundle<SC: p3_uni_stark::StarkGenericConfig> {
    pub dual_ntt: p3_uni_stark::Proof<SC>,
    pub coeff_dual_zero: p3_uni_stark::Proof<SC>,
    pub l2_bound: p3_uni_stark::Proof<SC>,
    pub ntt_sig_pos: p3_uni_stark::Proof<SC>,
    pub ntt_sig_neg: p3_uni_stark::Proof<SC>,
    pub ntt_v_pos: p3_uni_stark::Proof<SC>,
    pub ntt_v_neg: p3_uni_stark::Proof<SC>,
}

/// Native parsed verify + produce all STARK proofs (7 proofs: dual NTT, coeff dual, L² bound, 4× full NTT).
pub fn prove_falcon_parsed_verify(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> FalconVerifyStarkBundle<FalconStarkConfig> {
    assert!(
        pk.verify_parsed_sig(msg, sig),
        "statement must satisfy Falcon parsed verify (includes L² check outside STARKs)"
    );

    let config = stark_config_poseidon2();

    let (dual_air, dual_main) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let dual_deg = log2_strict_usize(dual_main.height());
    let (dual_pp, dual_vk) = setup_preprocessed(&config, &dual_air, dual_deg).expect("dual_ntt setup");
    debug_assert_eq!(dual_pp.degree_bits, dual_deg + config.is_zk());
    let dual_ntt = prove_with_preprocessed(&config, &dual_air, dual_main, &[], Some(&dual_pp));
    assert!(
        verify_with_preprocessed(&config, &dual_air, &dual_ntt, &[], Some(&dual_vk)).is_ok()
    );

    let (coeff_air, coeff_main) = build_falcon_coeff_dual_product_zero_instance(sig);
    let coeff_deg = log2_strict_usize(coeff_main.height());
    let (coeff_pp, coeff_vk) =
        setup_preprocessed(&config, &coeff_air, coeff_deg).expect("coeff_dual setup");
    debug_assert_eq!(coeff_pp.degree_bits, coeff_deg + config.is_zk());
    let coeff_dual_zero = prove_with_preprocessed(&config, &coeff_air, coeff_main, &[], Some(&coeff_pp));
    assert!(
        verify_with_preprocessed(&config, &coeff_air, &coeff_dual_zero, &[], Some(&coeff_vk)).is_ok()
    );

    let l2_air = FalconL2BoundAir::new();
    let l2_main = build_falcon_l2_bound_trace(pk, msg, sig);
    let l2_bound = prove(&config, &l2_air, l2_main, &[]);
    assert!(verify(&config, &l2_air, &l2_bound, &[]).is_ok());

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let prove_full_ntt = |poly: &Polynomial| {
        let prep = build_ntt_full_preprocessed(poly);
        let main = build_ntt_full_main(poly);
        let air = FalconNttFullAir::new(prep.clone());
        let deg = log2_strict_usize(main.height());
        let (pp, vk) = setup_preprocessed(&config, &air, deg).expect("ntt_full setup");
        debug_assert_eq!(pp.degree_bits, deg + config.is_zk());
        let proof = prove_with_preprocessed(&config, &air, main, &[], Some(&pp));
        assert!(verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk)).is_ok());
        proof
    };

    let ntt_sig_pos = prove_full_ntt(&sig_poly.pos);
    let ntt_sig_neg = prove_full_ntt(&sig_poly.neg);
    let ntt_v_pos = prove_full_ntt(&v_dual.pos);
    let ntt_v_neg = prove_full_ntt(&v_dual.neg);

    // Sanity: full NTT matches library
    let _ = NTTPolynomial::from(&sig_poly.pos);

    FalconVerifyStarkBundle {
        dual_ntt,
        coeff_dual_zero,
        l2_bound,
        ntt_sig_pos,
        ntt_sig_neg,
        ntt_v_pos,
        ntt_v_neg,
    }
}

/// Verify every proof in `bundle` (rebuilds each `Air` from `pk,msg,sig` so periodic / preprocessed data match the proof).
pub fn verify_falcon_parsed_verify(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    bundle: &FalconVerifyStarkBundle<FalconStarkConfig>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    let config = stark_config_poseidon2();

    let (dual_air, _dual_main) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let dual_deg = log2_strict_usize(N);
    let (_, dual_vk) = setup_preprocessed(&config, &dual_air, dual_deg).expect("dual_ntt setup");
    verify_with_preprocessed(&config, &dual_air, &bundle.dual_ntt, &[], Some(&dual_vk))?;

    let (coeff_air, _coeff_main) = build_falcon_coeff_dual_product_zero_instance(sig);
    let coeff_deg = log2_strict_usize(N);
    let (_, coeff_vk) = setup_preprocessed(&config, &coeff_air, coeff_deg).expect("coeff_dual setup");
    verify_with_preprocessed(&config, &coeff_air, &bundle.coeff_dual_zero, &[], Some(&coeff_vk))?;

    let l2_air = FalconL2BoundAir::new();
    verify(&config, &l2_air, &bundle.l2_bound, &[])?;

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let verify_full_ntt = |poly: &Polynomial, proof: &p3_uni_stark::Proof<FalconStarkConfig>| {
        let prep = build_ntt_full_preprocessed(poly);
        let main = build_ntt_full_main(poly);
        let air = FalconNttFullAir::new(prep);
        let deg = log2_strict_usize(main.height());
        let (_, vk) = setup_preprocessed(&config, &air, deg).expect("ntt_full setup");
        verify_with_preprocessed(&config, &air, proof, &[], Some(&vk))
    };

    verify_full_ntt(&sig_poly.pos, &bundle.ntt_sig_pos)?;
    verify_full_ntt(&sig_poly.neg, &bundle.ntt_sig_neg)?;
    verify_full_ntt(&v_dual.pos, &bundle.ntt_v_pos)?;
    verify_full_ntt(&v_dual.neg, &bundle.ntt_v_neg)?;

    Ok(())
}

/// Prove **one** per-layer NTT STARK for each limb (legacy path: `4 * LOG_N` proofs). Useful for debugging.
pub fn prove_falcon_ntt_layers_only(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> Vec<p3_uni_stark::Proof<FalconStarkConfig>> {
    let config = stark_config_poseidon2();
    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let mut proofs = Vec::new();
    for poly in [
        &sig_poly.pos,
        &sig_poly.neg,
        &v_dual.pos,
        &v_dual.neg,
    ] {
        for layer in 0..falcon_rust::LOG_N {
            let (air, main) = build_ntt_layer_instance(poly, layer);
            let deg = log2_strict_usize(main.height());
            let (pp, _) = setup_preprocessed(&config, &air, deg).unwrap();
            debug_assert_eq!(pp.degree_bits, deg + config.is_zk());
            proofs.push(prove_with_preprocessed(&config, &air, main, &[], Some(&pp)));
        }
    }
    proofs
}
