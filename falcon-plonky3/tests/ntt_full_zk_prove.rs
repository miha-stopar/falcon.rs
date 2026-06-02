use falcon_plonky3::{
    air::{build_ntt_full_main, FalconNttFullAir, StatementBoundAir},
    full_verify::FALCON_STATEMENT_DIGEST_LEN,
    stark_config_poseidon2_zk, FalconCredentialVerifyKeys, FalconStarkZkConfig,
};
use falcon_rust::{KeyPair, Polynomial};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{prove_with_preprocessed, verify_with_preprocessed};

#[test]
fn ntt_full_zk_with_preprocessed_vk() {
    let keypair = KeyPair::keygen();
    let sig = keypair.secret_key.sign_with_seed(b"s", b"msg");
    let poly: Polynomial = (&sig).into();

    let config = stark_config_poseidon2_zk();
    let keys = FalconCredentialVerifyKeys::<FalconStarkZkConfig>::setup(&config);
    let digest = [KoalaBear::ZERO; FALCON_STATEMENT_DIGEST_LEN];
    let air = StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
    let main = build_ntt_full_main(&poly);
    let proof = prove_with_preprocessed(&config, &air, main, &digest, Some(&keys.ntt_full_pp));
    verify_with_preprocessed(&config, &air, &proof, &digest, Some(&keys.ntt_full_vk)).unwrap();
}
