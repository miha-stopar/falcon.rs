use falcon_plonky3::{
    prove_credential, stark_config_poseidon2, verify_credential, FalconCredentialPublicInputs,
    FalconCredentialVerifyKeys, FalconStarkConfig,
};
use falcon_rust::KeyPair;

#[test]
fn credential_prove_verify_with_fixed_keys() {
    let keypair = KeyPair::keygen();
    let msg = b"zk credential presentation";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-cred", msg.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg.as_ref(), &sig));

    let config = stark_config_poseidon2();
    let keys = FalconCredentialVerifyKeys::<FalconStarkConfig>::setup(&config);
    let public = FalconCredentialPublicInputs::from_presentation(&keypair.public_key, msg, &sig);

    let proof = prove_credential(&config, &keys, &public, &sig);
    verify_credential(&config, &keys, &public, &proof).expect("credential verify failed");
}

#[test]
fn credential_prove_verify_zk_config() {
    use falcon_plonky3::{
        prove_credential_zk, stark_config_poseidon2_zk, verify_credential_zk, FalconStarkZkConfig,
    };

    let keypair = KeyPair::keygen();
    let msg = b"zk credential presentation";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-cred-zk", msg.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg.as_ref(), &sig));

    let config = stark_config_poseidon2_zk();
    let keys = FalconCredentialVerifyKeys::<FalconStarkZkConfig>::setup(&config);
    let public = FalconCredentialPublicInputs::from_presentation(&keypair.public_key, msg, &sig);

    let proof = prove_credential_zk(&config, &keys, &public, &sig);
    verify_credential_zk(&config, &keys, &public, &proof).expect("credential zk verify failed");
}

#[test]
fn ntt_full_vk_is_reusable_across_polynomials() {
    use falcon_plonky3::air::{build_ntt_full_main, FalconNttFullAir, StatementBoundAir};
    use falcon_plonky3::full_verify::FALCON_STATEMENT_DIGEST_LEN;
    use falcon_rust::Polynomial;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_uni_stark::{prove_with_preprocessed, verify_with_preprocessed};

    let keypair = KeyPair::keygen();
    let msg = b"vk reuse";
    let sig = keypair.secret_key.sign_with_seed(b"s", msg.as_ref());
    let poly_a: Polynomial = (&sig).into();
    let poly_b = poly_a.clone();

    let config = stark_config_poseidon2();
    let keys = FalconCredentialVerifyKeys::<FalconStarkConfig>::setup(&config);
    let digest = [KoalaBear::ZERO; 8];
    let air = StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);

    let main = build_ntt_full_main(&poly_a);
    let proof_a = prove_with_preprocessed(&config, &air, main, &digest, Some(&keys.ntt_full_pp));
    verify_with_preprocessed(&config, &air, &proof_a, &digest, Some(&keys.ntt_full_vk)).unwrap();

    let main_b = build_ntt_full_main(&poly_b);
    let proof_b = prove_with_preprocessed(&config, &air, main_b, &digest, Some(&keys.ntt_full_pp));
    verify_with_preprocessed(&config, &air, &proof_b, &digest, Some(&keys.ntt_full_vk)).unwrap();
}
