use falcon_plonky3::{
    prove_falcon_parsed_verify_single_stark, verify_falcon_parsed_verify_single_stark,
};
use falcon_rust::KeyPair;

#[test]
#[ignore = "experimental unified AIR: OOD mismatch — see docs/unified_single_stark_ood.md"]
fn prove_and_verify_unified_single_stark_parsed_verify() {
    let keypair = KeyPair::keygen();
    let msg = b"plonky3 falcon unified single-STARK parsed-verify";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-unified-single", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let proof = prove_falcon_parsed_verify_single_stark(&keypair.public_key, msg.as_ref(), &sig);
    verify_falcon_parsed_verify_single_stark(&keypair.public_key, msg.as_ref(), &sig, &proof)
        .expect("unified single-STARK verification failed");
}
