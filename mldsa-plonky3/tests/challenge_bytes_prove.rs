use mldsa_plonky3::{build_ml_dsa44_challenge_trace, challenge_air, stark_config_poseidon2};
use ml_dsa::signature::Keypair;
use ml_dsa::{B32, KeyGen, MlDsa44};
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};
use p3_util::log2_strict_usize;

#[test]
fn prove_verify_ml_dsa44_challenge_bytes() {
    let sk = MlDsa44::from_seed(&B32::default());
    let vk = sk.verifying_key();
    let msg = b"mldsa-plonky3 ML-DSA-44 challenge bootstrap";
    let rnd = B32::default();
    let sig = sk.signing_key().sign_internal(&[msg], &rnd);

    assert!(
        vk.verify_internal(msg, &sig),
        "library ML-DSA.Verify_internal must accept signature"
    );

    let config = stark_config_poseidon2();
    let air = challenge_air();
    let trace = build_ml_dsa44_challenge_trace(&vk, msg, &sig);

    assert_eq!(trace.height(), 32);
    assert!(trace.height().is_power_of_two());

    let degree_bits = log2_strict_usize(trace.height());
    assert_eq!(degree_bits, 5);

    let proof = prove(&config, &air, trace, &[]);
    verify(&config, &air, &proof, &[]).expect("STARK verification failed");
}
