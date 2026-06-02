//! Keccak-f sub-STARK for Falcon SHAKE `process_block` steps (Phase C sponge).

use falcon_plonky3::{
    air::StatementBoundAir,
    credential::falcon_credential_verify_digest,
    hash::{hash_to_point, prove_shake_keccak},
    stark_config_poseidon2, FalconCredentialPublicInputs,
};
use falcon_rust::KeyPair;
use p3_keccak_air::KeccakAir;
use p3_uni_stark::verify;

#[test]
fn shake_keccak_prove_verify() {
    let keypair = KeyPair::keygen();
    let msg = b"zk credential presentation";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-keccak", msg.as_ref());
    let public = FalconCredentialPublicInputs::from_presentation(&keypair.public_key, msg, &sig);
    let digest = falcon_credential_verify_digest(&public);

    let result = hash_to_point(msg, sig.nonce());
    let config = stark_config_poseidon2();
    let proof = prove_shake_keccak(&config, &result, &digest);

    let air = StatementBoundAir::new(KeccakAir {}, 8);
    verify(&config, &air, &proof, &digest).expect("shake keccak verify");
}
