use falcon_plonky3::{
    falcon_statement_digest, prove_falcon_parsed_verify, verify_falcon_parsed_verify,
};
use falcon_rust::KeyPair;

#[test]
fn prove_and_verify_full_parsed_verify_bundle() {
    let keypair = KeyPair::keygen();
    let msg = b"plonky3 falcon full parsed-verify bundle";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-full-verify", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let bundle = prove_falcon_parsed_verify(&keypair.public_key, msg.as_ref(), &sig);
    verify_falcon_parsed_verify(&keypair.public_key, msg.as_ref(), &sig, &bundle)
        .expect("full verify bundle verification failed");
}

#[test]
fn statement_digest_is_deterministic_and_input_sensitive() {
    let keypair = KeyPair::keygen();
    let msg = b"digest test message";
    let sig = keypair.secret_key.sign_with_seed(b"seed-d", msg.as_ref());

    let d = falcon_statement_digest(&keypair.public_key, msg.as_ref(), &sig);
    assert_eq!(
        d,
        falcon_statement_digest(&keypair.public_key, msg.as_ref(), &sig),
        "digest must be deterministic"
    );

    // Different message → different digest (hm = H(msg, nonce) and the absorbed bytes change).
    let other_msg = b"digest test message!";
    assert_ne!(
        d,
        falcon_statement_digest(&keypair.public_key, other_msg.as_ref(), &sig),
        "digest must depend on the message"
    );

    // Different key/signature → different digest.
    let kp2 = KeyPair::keygen();
    let sig2 = kp2.secret_key.sign_with_seed(b"seed-d", msg.as_ref());
    assert_ne!(
        d,
        falcon_statement_digest(&kp2.public_key, msg.as_ref(), &sig2),
        "digest must depend on (pk, sig)"
    );
}
