use falcon_plonky3::{
    build_falcon_l2_bound_preprocessed, build_falcon_l2_bound_trace, stark_config_poseidon2,
    FalconL2BoundAir,
};
use falcon_rust::KeyPair;
use p3_air::check_constraints;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_strict_usize;

#[test]
fn l2_trace_satisfies_air() {
    let keypair = KeyPair::keygen();
    let msg = b"l2 check";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"s", msg.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg.as_ref(), &sig));
    let prep = build_falcon_l2_bound_preprocessed(&keypair.public_key, msg.as_ref(), &sig);
    let air = FalconL2BoundAir::new(prep);
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
    let prep = build_falcon_l2_bound_preprocessed(&keypair.public_key, msg.as_ref(), &sig);
    let air = FalconL2BoundAir::new(prep);
    let trace = build_falcon_l2_bound_trace(&keypair.public_key, msg.as_ref(), &sig);
    assert_eq!(trace.height(), 4 * falcon_rust::N);
    assert!(trace.height().is_power_of_two());

    let deg = log2_strict_usize(trace.height());
    let (pp, vk) = setup_preprocessed(&config, &air, deg).expect("l2 setup");
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pp));
    verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk))
        .expect("L2 bound verification failed");
}

/// Soundness regression: the L² witness is now *bound* to the statement coefficients via the
/// preprocessed reference. A norm-trace built from a different signature (its own internally
/// consistent accumulation) must be rejected against another statement's coefficients.
/// Before the binding fix this trace would have satisfied the AIR.
#[test]
#[should_panic(expected = "constraint")]
fn l2_trace_from_other_signature_is_rejected() {
    let keypair = KeyPair::keygen();
    let msg_a = b"statement A";
    let sig_a = keypair.secret_key.sign_with_seed(b"seed-a", msg_a.as_ref());
    let msg_b = b"statement B (unrelated)";
    let sig_b = keypair.secret_key.sign_with_seed(b"seed-b", msg_b.as_ref());
    assert!(keypair.public_key.verify_parsed_sig(msg_a.as_ref(), &sig_a));
    assert!(keypair.public_key.verify_parsed_sig(msg_b.as_ref(), &sig_b));

    // Verifier-rebuilt reference is for statement A...
    let prep_a = build_falcon_l2_bound_preprocessed(&keypair.public_key, msg_a.as_ref(), &sig_a);
    let air = FalconL2BoundAir::new(prep_a);
    // ...but the prover supplies the (valid-in-isolation) norm trace of statement B.
    let trace_b = build_falcon_l2_bound_trace(&keypair.public_key, msg_b.as_ref(), &sig_b);

    // `check_constraints` asserts on the first violated row (the `e == coeff_ref` binding).
    check_constraints(&air, &trace_b, &[]);
}
