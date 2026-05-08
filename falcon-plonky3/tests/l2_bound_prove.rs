use falcon_plonky3::{build_falcon_l2_bound_trace, stark_config_poseidon2, FalconL2BoundAir};
use falcon_rust::KeyPair;
use p3_air::check_constraints;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};

#[test]
fn l2_trace_satisfies_air() {
    let keypair = KeyPair::keygen();
    let msg = b"l2 check";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"s", msg.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg.as_ref(), &sig));
    let air = FalconL2BoundAir::new();
    let trace = build_falcon_l2_bound_trace(&keypair.public_key, msg.as_ref(), &sig);
    check_constraints(&air, &trace, &[]);
}

#[test]
fn prove_and_verify_l2_bound_air() {
    let keypair = KeyPair::keygen();
    let msg = b"l2 bound STARK";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-l2", msg.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg.as_ref(), &sig));

    let config = stark_config_poseidon2();
    let air = FalconL2BoundAir::new();
    let trace = build_falcon_l2_bound_trace(&keypair.public_key, msg.as_ref(), &sig);
    assert_eq!(trace.height(), 4 * falcon_rust::N);
    assert!(trace.height().is_power_of_two());

    let proof = prove(&config, &air, trace, &[]);
    verify(&config, &air, &proof, &[]).expect("L2 bound verification failed");
}
