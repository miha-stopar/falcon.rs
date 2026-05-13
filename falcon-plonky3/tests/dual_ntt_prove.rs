use falcon_plonky3::{build_falcon_dual_ntt_instance, stark_config_poseidon2};
use falcon_rust::KeyPair;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_strict_usize;

#[test]
fn prove_and_verify_dual_ntt_equation() {
    let keypair = KeyPair::keygen();
    let msg = b"plonky3 falcon port smoke test";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let config = stark_config_poseidon2();

    let (air, main_trace) = build_falcon_dual_ntt_instance(&keypair.public_key, msg.as_ref(), &sig);

    let deg = log2_strict_usize(main_trace.height());
    let (pp, vk) = setup_preprocessed(&config, &air, deg).unwrap();
    let proof = prove_with_preprocessed(&config, &air, main_trace, &[], Some(&pp));

    verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk)).expect("verification failed");
}
