use falcon_plonky3::{
    build_falcon_coeff_dual_product_zero_trace, stark_config_poseidon2, FalconCoeffDualProductZeroAir,
};
use falcon_rust::KeyPair;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};

#[test]
fn prove_and_verify_coeff_dual_product_zero() {
    let keypair = KeyPair::keygen();
    let msg = b"coeff dual zero STARK";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let config = stark_config_poseidon2();
    let air = FalconCoeffDualProductZeroAir::new();
    let trace = build_falcon_coeff_dual_product_zero_trace(&sig);

    assert_eq!(trace.height(), falcon_rust::N);
    assert!(trace.height().is_power_of_two());

    let proof = prove(&config, &air, trace, &[]);
    verify(&config, &air, &proof, &[]).expect("verification failed");
}
