//! End-to-end Falcon **parsed-verify** decomposition into Plonky3 STARKs (transparent setting).
//!
//! Verifier-side periodic inputs (`pk_ntt`, `hm_ntt` per index, period `N`) and per-layer NTT
//! inputs in preprocessed traces for full NTT are derived in the clear from `(pk, msg, sig)` the
//! same way as in [`crate::witness::build_falcon_dual_ntt_instance`].
//!
//! ## Verifier-facing statement
//!
//! - **Inputs:** [`verify_falcon_parsed_verify`] takes `pk`, `msg`, `sig`, and the bundle. It does
//!   **not** take prover-supplied `pk_ntt` / `hm_ntt` blobs separately; it rebuilds every `Air` from `(pk, msg, sig)`.
//! - **Dual-NTT:** proves the mod-`q` congruence for the main trace **given** those periodic
//!   tables, and **equality** of the NTT limbs to verifier-rebuilt **preprocessed** references
//!   (same construction as [`crate::witness::build_falcon_dual_ntt_instance`]).
//! - **Composition:** the seven proofs use **separate** Fiat–Shamir transcripts, but each transcript
//!   is bound to a common **statement digest** ([`falcon_statement_digest`]) supplied as
//!   `public_values` via [`StatementBoundAir`], so the bundle is tied to one `(pk, msg, sig)` and the
//!   sub-proofs cannot be mixed across statements. Dual-NTT, coeff dual-zero, and L² additionally
//!   **pin** witness columns to verifier-rebuilt preprocessed data. See the crate
//!   **[`README.md`](../README.md#verifier-facing-statement)** for the full trust-model table.
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
//!    [`falcon_rust::SIG_L2_BOUND`] (same centering rule as [`falcon_rust::Polynomial::l2_norm`]),
//!    with each per-row coefficient **bound** to a verifier-rebuilt preprocessed reference
//!    (`sig_pos`, `sig_neg`, `v_pos`, `v_neg`). Without this binding the norm bound could be
//!    satisfied with unrelated coefficients (e.g. all zero); the binding ties it to the statement.
//!
//! Native [`falcon_rust::PublicKey::verify_parsed_sig`] is still used before proving to ensure a valid
//! witness (hash / parsing); the L² STARK duplicates the norm bound in-circuit for transparency.
//!
//! **Experimental single-STARK:** [`prove_falcon_parsed_verify_single_stark`] stacks the same logical
//! constraints into one wider trace (segment selectors); compare timing against the default seven-proof path.

use std::time::{Duration, Instant};

use falcon_rust::{DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, N};

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, StarkGenericConfig,
};
use p3_util::log2_strict_usize;

use crate::air::{build_ntt_full_main, FalconNttFullAir, StatementBoundAir};
use crate::config::FalconStarkConfig;
use crate::air::unified_trace_height;
use crate::witness::{
    build_falcon_coeff_dual_product_zero_instance, build_falcon_dual_ntt_instance,
    build_falcon_l2_bound_preprocessed, build_falcon_l2_bound_trace,
    build_falcon_unified_parsed_verify_air, build_falcon_unified_parsed_verify_instance,
    build_ntt_layer_instance,
};
use crate::{FalconL2BoundAir, stark_config_poseidon2};

/// Number of [`KoalaBear`] elements in a Falcon statement digest (Poseidon2 sponge output).
pub const FALCON_STATEMENT_DIGEST_LEN: usize = 8;

/// Deterministic digest of the statement `(pk, msg, sig)` as field elements.
///
/// Bound into every sub-proof's Fiat–Shamir transcript via `public_values` (see
/// [`StatementBoundAir`]), so the seven proofs are explicitly tied to **one** statement and to each
/// other — not only implicitly via the verifier rebuilding each AIR. Prover and verifier compute it
/// identically from `(pk, msg, sig)`. It is observed into the transcript, not constrained in-circuit.
pub fn falcon_statement_digest(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> [KoalaBear; FALCON_STATEMENT_DIGEST_LEN] {
    let pk_poly: Polynomial = pk.into();
    let sig_poly: DualPolynomial = sig.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());

    let fe = |x: u32| KoalaBear::from_u32(x);
    let mut input: Vec<KoalaBear> = Vec::new();
    // Domain separation + lengths, then the full statement (pk, msg, sig coeffs, and hm = H(msg, nonce)).
    input.push(fe(0x4641_4C32)); // "FAL2"
    input.push(fe(N as u32));
    input.push(fe(msg.len() as u32));
    input.extend(msg.iter().map(|&b| fe(u32::from(b))));
    input.extend(pk_poly.coeff().iter().map(|&c| fe(u32::from(c))));
    input.extend(sig_poly.pos.coeff().iter().map(|&c| fe(u32::from(c))));
    input.extend(sig_poly.neg.coeff().iter().map(|&c| fe(u32::from(c))));
    input.extend(hm.coeff().iter().map(|&c| fe(u32::from(c))));

    let perm = default_koalabear_poseidon2_16();
    let hasher = PaddingFreeSponge::<Poseidon2KoalaBear<16>, 16, 8, 8>::new(perm);
    hasher.hash_iter(input)
}

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

/// Wall-clock split for [`verify_falcon_parsed_verify`]: native/instance work vs proof-system verification.
///
/// `instance_prep` includes rebuilding AIRs from `(pk, msg, sig)` and running `setup_preprocessed` for each
/// sub-proof (PCS commitments to selectors / preprocessed traces), not only hashing or small table derivation.
/// In typical configurations the dominant cost is [`Self::stark_crypto_verify`]—seven STARK verifiers (FRI,
/// openings, …)—not recomputing `pk_ntt` / `hm_ntt`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FalconParsedVerifyVerifierBreakdown {
    pub instance_prep: Duration,
    pub stark_crypto_verify: Duration,
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
    let digest = falcon_statement_digest(pk, msg, sig);

    let (dual_air, dual_main) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
    let dual_deg = log2_strict_usize(dual_main.height());
    let (dual_pp, dual_vk) = setup_preprocessed(&config, &dual_air, dual_deg).expect("dual_ntt setup");
    debug_assert_eq!(dual_pp.degree_bits, dual_deg + config.is_zk());
    let dual_ntt = prove_with_preprocessed(&config, &dual_air, dual_main, &digest, Some(&dual_pp));
    assert!(
        verify_with_preprocessed(&config, &dual_air, &dual_ntt, &digest, Some(&dual_vk)).is_ok()
    );

    let (coeff_air, coeff_main) = build_falcon_coeff_dual_product_zero_instance(sig);
    let coeff_air = StatementBoundAir::new(coeff_air, FALCON_STATEMENT_DIGEST_LEN);
    let coeff_deg = log2_strict_usize(coeff_main.height());
    let (coeff_pp, coeff_vk) =
        setup_preprocessed(&config, &coeff_air, coeff_deg).expect("coeff_dual setup");
    debug_assert_eq!(coeff_pp.degree_bits, coeff_deg + config.is_zk());
    let coeff_dual_zero =
        prove_with_preprocessed(&config, &coeff_air, coeff_main, &digest, Some(&coeff_pp));
    assert!(
        verify_with_preprocessed(&config, &coeff_air, &coeff_dual_zero, &digest, Some(&coeff_vk))
            .is_ok()
    );

    let l2_prep = build_falcon_l2_bound_preprocessed(pk, msg, sig);
    let l2_air = StatementBoundAir::new(FalconL2BoundAir::new(l2_prep), FALCON_STATEMENT_DIGEST_LEN);
    let l2_main = build_falcon_l2_bound_trace(pk, msg, sig);
    let l2_deg = log2_strict_usize(l2_main.height());
    let (l2_pp, l2_vk) = setup_preprocessed(&config, &l2_air, l2_deg).expect("l2_bound setup");
    debug_assert_eq!(l2_pp.degree_bits, l2_deg + config.is_zk());
    let l2_bound = prove_with_preprocessed(&config, &l2_air, l2_main, &digest, Some(&l2_pp));
    assert!(verify_with_preprocessed(&config, &l2_air, &l2_bound, &digest, Some(&l2_vk)).is_ok());

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let prove_full_ntt = |poly: &Polynomial| {
        let main = build_ntt_full_main(poly);
        let air = StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
        let deg = log2_strict_usize(main.height());
        let (pp, vk) = setup_preprocessed(&config, &air, deg).expect("ntt_full setup");
        debug_assert_eq!(pp.degree_bits, deg + config.is_zk());
        let proof = prove_with_preprocessed(&config, &air, main, &digest, Some(&pp));
        assert!(verify_with_preprocessed(&config, &air, &proof, &digest, Some(&vk)).is_ok());
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

/// Parsed-verify proof as a **single** STARK over [`crate::air::FalconUnifiedParsedVerifyAir`].
///
/// **Experimental:** still hits `OodEvaluationMismatch` on valid witnesses despite `check_constraints`
/// accepting the trace (details, bisection, and ruled-out causes: **`docs/unified_single_stark_ood.md`**).
/// Prefer [`prove_falcon_parsed_verify`] for a sound bundle. Kept for benchmarking trace generation /
/// proving cost vs seven proofs.
pub fn prove_falcon_parsed_verify_single_stark(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> p3_uni_stark::Proof<FalconStarkConfig> {
    assert!(
        pk.verify_parsed_sig(msg, sig),
        "statement must satisfy Falcon parsed verify (includes L² check outside STARKs)"
    );

    let config = stark_config_poseidon2();
    let (air, main) = build_falcon_unified_parsed_verify_instance(pk, msg, sig);
    debug_assert_eq!(main.height(), unified_trace_height());
    let degree_bits = log2_strict_usize(main.height());
    let (pp, _vk) = setup_preprocessed(&config, &air, degree_bits).expect("unified parsed-verify setup");
    debug_assert_eq!(pp.degree_bits, degree_bits + config.is_zk());
    let proof = prove_with_preprocessed(&config, &air, main, &[], Some(&pp));
    proof
}

/// Verify [`prove_falcon_parsed_verify_single_stark`] (rebuilds the unified AIR from `(pk, msg, sig)`).
///
/// **Experimental:** same OOD issue as [`prove_falcon_parsed_verify_single_stark`] — see **`docs/unified_single_stark_ood.md`**.
pub fn verify_falcon_parsed_verify_single_stark(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    proof: &p3_uni_stark::Proof<FalconStarkConfig>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    let config = stark_config_poseidon2();
    let air = build_falcon_unified_parsed_verify_air(pk, msg, sig);
    let zk_ext = config.is_zk();
    let base_degree_bits = proof.degree_bits.checked_sub(zk_ext).expect(
        "uni-stark proof.degree_bits must be at least the ZK trace extension flag",
    );
    let (_, vk) = setup_preprocessed(&config, &air, base_degree_bits).expect("unified setup");
    verify_with_preprocessed(&config, &air, proof, &[], Some(&vk))
}

/// Verify every proof in `bundle` (rebuilds each `Air` from `pk,msg,sig` so periodic / preprocessed data match the proof).
///
/// This runs the seven sub-verifiers **in parallel** (independent `Air`s / transcripts). For sequential timing
/// splits (e.g. benchmarks), use [`verify_falcon_parsed_verify_with_breakdown`].
pub fn verify_falcon_parsed_verify(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    bundle: &FalconVerifyStarkBundle<FalconStarkConfig>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    verify_falcon_parsed_verify_parallel(pk, msg, sig, bundle)
}

fn verify_falcon_parsed_verify_parallel(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    bundle: &FalconVerifyStarkBundle<FalconStarkConfig>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);
    let digest = falcon_statement_digest(pk, msg, sig);

    type VerErr = p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>;

    std::thread::scope(|s| {
        let digest = &digest;
        let h1 = s.spawn(move || {
            let config = stark_config_poseidon2();
            let (dual_air, _) = build_falcon_dual_ntt_instance(pk, msg, sig);
            let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
            let (_, dual_vk) =
                setup_preprocessed(&config, &dual_air, log2_strict_usize(N)).expect("dual_ntt setup");
            verify_with_preprocessed(&config, &dual_air, &bundle.dual_ntt, digest, Some(&dual_vk))
        });
        let h2 = s.spawn(move || {
            let config = stark_config_poseidon2();
            let (coeff_air, _) = build_falcon_coeff_dual_product_zero_instance(sig);
            let coeff_air = StatementBoundAir::new(coeff_air, FALCON_STATEMENT_DIGEST_LEN);
            let (_, coeff_vk) =
                setup_preprocessed(&config, &coeff_air, log2_strict_usize(N)).expect("coeff_dual setup");
            verify_with_preprocessed(&config, &coeff_air, &bundle.coeff_dual_zero, digest, Some(&coeff_vk))
        });
        let h3 = s.spawn(move || {
            let config = stark_config_poseidon2();
            let l2_prep = build_falcon_l2_bound_preprocessed(pk, msg, sig);
            let l2_air =
                StatementBoundAir::new(FalconL2BoundAir::new(l2_prep), FALCON_STATEMENT_DIGEST_LEN);
            let (_, l2_vk) = setup_preprocessed(&config, &l2_air, log2_strict_usize(4 * N))
                .expect("l2_bound setup");
            verify_with_preprocessed(&config, &l2_air, &bundle.l2_bound, digest, Some(&l2_vk))
        });
        let h4 = s.spawn(move || {
            verify_ntt_full_subproof(&sig_poly.pos, &bundle.ntt_sig_pos, digest)
        });
        let h5 = s.spawn(move || {
            verify_ntt_full_subproof(&sig_poly.neg, &bundle.ntt_sig_neg, digest)
        });
        let h6 = s.spawn(move || {
            verify_ntt_full_subproof(&v_dual.pos, &bundle.ntt_v_pos, digest)
        });
        let h7 = s.spawn(move || {
            verify_ntt_full_subproof(&v_dual.neg, &bundle.ntt_v_neg, digest)
        });

        let mut first_err: Option<VerErr> = None;
        for h in [h1, h2, h3, h4, h5, h6, h7] {
            match h.join().unwrap() {
                Ok(()) => {}
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        match first_err {
            None => Ok(()),
            Some(e) => Err(e),
        }
    })
}

fn verify_ntt_full_subproof(
    poly: &Polynomial,
    proof: &p3_uni_stark::Proof<FalconStarkConfig>,
    digest: &[KoalaBear],
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    let config = stark_config_poseidon2();
    let main = build_ntt_full_main(poly);
    let air = StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
    let deg = log2_strict_usize(main.height());
    let (_, vk) = setup_preprocessed(&config, &air, deg).expect("ntt_full setup");
    verify_with_preprocessed(&config, &air, proof, digest, Some(&vk))
}

/// Same as [`verify_falcon_parsed_verify`], but returns how much time was spent in instance/key prep vs STARK verification.
///
/// **Runs sub-proof setup and verify sequentially** so `instance_prep` and `stark_crypto_verify` sum to wall time.
/// This split is useful for profiling; the default [`verify_falcon_parsed_verify`] path is parallel and faster.
pub fn verify_falcon_parsed_verify_with_breakdown(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
    bundle: &FalconVerifyStarkBundle<FalconStarkConfig>,
) -> Result<
    FalconParsedVerifyVerifierBreakdown,
    p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>,
> {
    let mut instance_prep = Duration::ZERO;
    let mut stark_crypto_verify = Duration::ZERO;
    let config = stark_config_poseidon2();
    let digest = falcon_statement_digest(pk, msg, sig);

    let t0 = Instant::now();
    let (dual_air, _dual_main) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
    let dual_deg = log2_strict_usize(N);
    let (_, dual_vk) = setup_preprocessed(&config, &dual_air, dual_deg).expect("dual_ntt setup");
    instance_prep += t0.elapsed();

    let t0 = Instant::now();
    verify_with_preprocessed(&config, &dual_air, &bundle.dual_ntt, &digest, Some(&dual_vk))?;
    stark_crypto_verify += t0.elapsed();

    let t0 = Instant::now();
    let (coeff_air, _coeff_main) = build_falcon_coeff_dual_product_zero_instance(sig);
    let coeff_air = StatementBoundAir::new(coeff_air, FALCON_STATEMENT_DIGEST_LEN);
    let coeff_deg = log2_strict_usize(N);
    let (_, coeff_vk) = setup_preprocessed(&config, &coeff_air, coeff_deg).expect("coeff_dual setup");
    instance_prep += t0.elapsed();

    let t0 = Instant::now();
    verify_with_preprocessed(&config, &coeff_air, &bundle.coeff_dual_zero, &digest, Some(&coeff_vk))?;
    stark_crypto_verify += t0.elapsed();

    let t0 = Instant::now();
    let l2_prep = build_falcon_l2_bound_preprocessed(pk, msg, sig);
    let l2_air = StatementBoundAir::new(FalconL2BoundAir::new(l2_prep), FALCON_STATEMENT_DIGEST_LEN);
    let (_, l2_vk) =
        setup_preprocessed(&config, &l2_air, log2_strict_usize(4 * N)).expect("l2_bound setup");
    instance_prep += t0.elapsed();

    let t0 = Instant::now();
    verify_with_preprocessed(&config, &l2_air, &bundle.l2_bound, &digest, Some(&l2_vk))?;
    stark_crypto_verify += t0.elapsed();

    let t0 = Instant::now();
    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);
    instance_prep += t0.elapsed();

    let verify_one_full_ntt = |poly: &Polynomial,
                               proof: &p3_uni_stark::Proof<FalconStarkConfig>,
                               instance_prep: &mut Duration,
                               stark_crypto_verify: &mut Duration|
     -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
        let t0 = Instant::now();
        let main = build_ntt_full_main(poly);
        let air = StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
        let deg = log2_strict_usize(main.height());
        let (_, vk) = setup_preprocessed(&config, &air, deg).expect("ntt_full setup");
        *instance_prep += t0.elapsed();

        let t0 = Instant::now();
        verify_with_preprocessed(&config, &air, proof, &digest, Some(&vk))?;
        *stark_crypto_verify += t0.elapsed();
        Ok(())
    };

    verify_one_full_ntt(
        &sig_poly.pos,
        &bundle.ntt_sig_pos,
        &mut instance_prep,
        &mut stark_crypto_verify,
    )?;
    verify_one_full_ntt(
        &sig_poly.neg,
        &bundle.ntt_sig_neg,
        &mut instance_prep,
        &mut stark_crypto_verify,
    )?;
    verify_one_full_ntt(
        &v_dual.pos,
        &bundle.ntt_v_pos,
        &mut instance_prep,
        &mut stark_crypto_verify,
    )?;
    verify_one_full_ntt(
        &v_dual.neg,
        &bundle.ntt_v_neg,
        &mut instance_prep,
        &mut stark_crypto_verify,
    )?;

    Ok(FalconParsedVerifyVerifierBreakdown {
        instance_prep,
        stark_crypto_verify,
    })
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
