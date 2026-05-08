use falcon_plonky3::{prove_falcon_parsed_verify, verify_falcon_parsed_verify};
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
