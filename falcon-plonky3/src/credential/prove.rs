//! Prove / verify a ZK credential presentation (private signature, public issuer + message).

use falcon_rust::{DualPolynomial, Polynomial, Signature};

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{prove, prove_with_preprocessed, verify, verify_with_preprocessed, Proof};

use crate::air::{
    build_ntt_full_main, FalconCoeffDualCredentialAir, FalconL2CredentialAir, FalconNttFullAir,
    StatementBoundAir,
};
use crate::config::FalconStarkConfig;
use crate::credential::keys::FalconCredentialVerifyKeys;
use crate::credential::public_inputs::FalconCredentialPublicInputs;
use crate::full_verify::FALCON_STATEMENT_DIGEST_LEN;
use crate::hash::hash_to_point;
use crate::hash::witness::build_hash_to_point_instance;
use crate::witness::{
    build_falcon_coeff_dual_product_zero_trace, build_falcon_dual_ntt_credential_air,
    build_falcon_dual_ntt_credential_instance, build_falcon_l2_bound_trace,
};

/// STARK bundle for one credential presentation (fixed NTT VK + in-circuit hash-to-point).
pub struct FalconCredentialProof {
    pub hash_to_point: Proof<FalconStarkConfig>,
    pub dual_ntt: Proof<FalconStarkConfig>,
    pub coeff_dual_zero: Proof<FalconStarkConfig>,
    pub l2_bound: Proof<FalconStarkConfig>,
    pub ntt_sig_pos: Proof<FalconStarkConfig>,
    pub ntt_sig_neg: Proof<FalconStarkConfig>,
    pub ntt_v_pos: Proof<FalconStarkConfig>,
    pub ntt_v_neg: Proof<FalconStarkConfig>,
}

/// Prove knowledge of a valid Falcon signature under `public.issuer_pk` for `public.msg`.
///
/// The signature is **private** (main trace only). The verifier never receives `sig`.
/// `public.hm` must equal the in-circuit hash-to-point output (prover sets this from `prove`).
pub fn prove_credential(
    config: &FalconStarkConfig,
    keys: &FalconCredentialVerifyKeys,
    public: &FalconCredentialPublicInputs<'_>,
    sig: &Signature,
) -> FalconCredentialProof {
    let nonce = sig.nonce();
    let shake = hash_to_point(public.msg, nonce);
    assert_eq!(
        public.hm, shake.hm,
        "public.hm must match in-circuit hash-to-point"
    );

    let digest = falcon_credential_verify_digest(public);

    let (htp_air, htp_main, _) = build_hash_to_point_instance(public.msg, nonce);
    let htp_air = StatementBoundAir::new(htp_air, FALCON_STATEMENT_DIGEST_LEN);
    let hash_to_point = prove(config, &htp_air, htp_main, &digest);

    let (dual_air, dual_main) =
        build_falcon_dual_ntt_credential_instance(public.issuer_pk, public.msg, sig);
    let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
    let dual_ntt = prove(config, &dual_air, dual_main, &digest);

    let coeff_air = StatementBoundAir::new(FalconCoeffDualCredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    let coeff_main = build_falcon_coeff_dual_product_zero_trace(sig);
    let coeff_dual_zero = if let Some(ref pp) = keys.coeff_dual_pp {
        prove_with_preprocessed(config, &coeff_air, coeff_main, &digest, Some(pp))
    } else {
        prove(config, &coeff_air, coeff_main, &digest)
    };

    let l2_air = StatementBoundAir::new(FalconL2CredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    let l2_main = build_falcon_l2_bound_trace(public.issuer_pk, public.msg, sig);
    let l2_bound = prove(config, &l2_air, l2_main, &digest);

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = public.issuer_pk.into();
    let hm = &public.hm;
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = *hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let prove_ntt = |poly: &Polynomial| {
        let air =
            StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
        let main = build_ntt_full_main(poly);
        prove_with_preprocessed(config, &air, main, &digest, Some(&keys.ntt_full_pp))
    };

    FalconCredentialProof {
        hash_to_point,
        dual_ntt,
        coeff_dual_zero,
        l2_bound,
        ntt_sig_pos: prove_ntt(&sig_poly.pos),
        ntt_sig_neg: prove_ntt(&sig_poly.neg),
        ntt_v_pos: prove_ntt(&v_dual.pos),
        ntt_v_neg: prove_ntt(&v_dual.neg),
    }
}

/// Verify using **fixed keys** and **public inputs only** (no secret signature).
pub fn verify_credential(
    config: &FalconStarkConfig,
    keys: &FalconCredentialVerifyKeys,
    public: &FalconCredentialPublicInputs<'_>,
    proof: &FalconCredentialProof,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<FalconStarkConfig>>> {
    let digest = falcon_credential_verify_digest(public);

    let htp_air = StatementBoundAir::new(
        crate::air::FalconHashToPointAir::new(public.msg.len()),
        FALCON_STATEMENT_DIGEST_LEN,
    );
    verify(config, &htp_air, &proof.hash_to_point, &digest)?;

    let dual_air = build_falcon_dual_ntt_credential_air(public.issuer_pk, &public.hm);
    let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
    verify(config, &dual_air, &proof.dual_ntt, &digest)?;

    let coeff_air = StatementBoundAir::new(FalconCoeffDualCredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    if let Some(ref vk) = keys.coeff_dual_vk {
        verify_with_preprocessed(config, &coeff_air, &proof.coeff_dual_zero, &digest, Some(vk))?;
    } else {
        verify(config, &coeff_air, &proof.coeff_dual_zero, &digest)?;
    }

    let l2_air = StatementBoundAir::new(FalconL2CredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    verify(config, &l2_air, &proof.l2_bound, &digest)?;

    let verify_ntt = |p: &Proof<FalconStarkConfig>| {
        let air =
            StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
        verify_with_preprocessed(config, &air, p, &digest, Some(&keys.ntt_full_vk))
    };
    verify_ntt(&proof.ntt_sig_pos)?;
    verify_ntt(&proof.ntt_sig_neg)?;
    verify_ntt(&proof.ntt_v_pos)?;
    verify_ntt(&proof.ntt_v_neg)?;
    Ok(())
}

/// Fiat–Shamir digest: public `(issuer_pk, msg, hm)` (no secret signature or nonce).
pub fn falcon_credential_verify_digest(
    public: &FalconCredentialPublicInputs<'_>,
) -> [KoalaBear; FALCON_STATEMENT_DIGEST_LEN] {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    let pk_poly: Polynomial = public.issuer_pk.into();
    let fe = |x: u32| KoalaBear::from_u32(x);
    let mut input: Vec<KoalaBear> = Vec::new();
    input.push(fe(0x4641_4C33)); // "FAL3" credential domain
    input.push(fe(falcon_rust::N as u32));
    input.push(fe(public.msg.len() as u32));
    input.extend(public.msg.iter().map(|&b| fe(u32::from(b))));
    input.extend(pk_poly.coeff().iter().map(|&c| fe(u32::from(c))));
    input.extend(public.hm.coeff().iter().map(|&c| fe(u32::from(c))));

    let perm = default_koalabear_poseidon2_16();
    let hasher = PaddingFreeSponge::<Poseidon2KoalaBear<16>, 16, 8, 8>::new(perm);
    hasher.hash_iter(input)
}
