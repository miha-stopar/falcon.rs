use falcon_plonky3::{
    build_falcon_coeff_dual_product_zero_instance, stark_config_poseidon2,
};
use falcon_rust::KeyPair;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_strict_usize;

#[test]
fn prove_and_verify_coeff_dual_product_zero() {
    let keypair = KeyPair::keygen();
    let msg = b"coeff dual zero STARK";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let config = stark_config_poseidon2();
    let (air, trace) = build_falcon_coeff_dual_product_zero_instance(&sig);

    assert_eq!(trace.height(), falcon_rust::N);
    assert!(trace.height().is_power_of_two());

    let deg = log2_strict_usize(trace.height());
    let (pp, vk) = setup_preprocessed(&config, &air, deg).unwrap();
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pp));
    verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk)).expect("verification failed");
}
