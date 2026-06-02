use falcon_plonky3::{
    air::{FalconCoeffDualCredentialAir, FalconL2CredentialAir, FalconNttFullAir, StatementBoundAir},
    credential::falcon_credential_verify_digest,
    full_verify::FALCON_STATEMENT_DIGEST_LEN,
    prove_credential_zk,
    stark_config_poseidon2_zk,
    witness::build_falcon_dual_ntt_credential_air,
    FalconCredentialPublicInputs, FalconCredentialVerifyKeys, FalconStarkZkConfig,
};
use falcon_rust::KeyPair;
use p3_uni_stark::{verify, verify_with_preprocessed};

#[test]
fn credential_zk_verify_each_subproof() {
    let keypair = KeyPair::keygen();
    let msg = b"zk credential presentation";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-zk-parts", msg.as_ref());

    let config = stark_config_poseidon2_zk();
    let keys = FalconCredentialVerifyKeys::<FalconStarkZkConfig>::setup(&config);
    let public = FalconCredentialPublicInputs::from_presentation(&keypair.public_key, msg, &sig);
    let digest = falcon_credential_verify_digest(&public);
    let proof = prove_credential_zk(&config, &keys, &public, &sig);

    let keccak_air = StatementBoundAir::new(p3_keccak_air::KeccakAir {}, FALCON_STATEMENT_DIGEST_LEN);
    verify(&config, &keccak_air, &proof.shake_keccak, &digest).expect("shake_keccak");

    let htp_air = StatementBoundAir::new(
        falcon_plonky3::air::FalconHashToPointAir::new(msg.len()),
        FALCON_STATEMENT_DIGEST_LEN,
    );
    verify(&config, &htp_air, &proof.hash_to_point, &digest).expect("hash_to_point");

    let dual_air = build_falcon_dual_ntt_credential_air(&keypair.public_key, &public.hm);
    let dual_air = StatementBoundAir::new(dual_air, FALCON_STATEMENT_DIGEST_LEN);
    verify(&config, &dual_air, &proof.dual_ntt, &digest).expect("dual_ntt");

    let coeff_air =
        StatementBoundAir::new(FalconCoeffDualCredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    verify(&config, &coeff_air, &proof.coeff_dual_zero, &digest).expect("coeff_dual_zero");

    let l2_air = StatementBoundAir::new(FalconL2CredentialAir, FALCON_STATEMENT_DIGEST_LEN);
    verify(&config, &l2_air, &proof.l2_bound, &digest).expect("l2_bound");

    let ntt_air =
        StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
    verify_with_preprocessed(&config, &ntt_air, &proof.ntt_sig_pos, &digest, Some(&keys.ntt_full_vk))
        .expect("ntt_sig_pos");
    verify_with_preprocessed(&config, &ntt_air, &proof.ntt_sig_neg, &digest, Some(&keys.ntt_full_vk))
        .expect("ntt_sig_neg");
    verify_with_preprocessed(&config, &ntt_air, &proof.ntt_v_pos, &digest, Some(&keys.ntt_full_vk))
        .expect("ntt_v_pos");
    verify_with_preprocessed(&config, &ntt_air, &proof.ntt_v_neg, &digest, Some(&keys.ntt_full_vk))
        .expect("ntt_v_neg");
}
