//! Compare wall-clock time for Falcon signature verification statements across:
//! - UltraPlonk + KZG (jellyfish `PlonkKzgSnark`, `falcon-plonk` circuit)
//! - Groth16 / R1CS (`falcon-r1cs`)
//! - Plonky3 STARK bundle (`falcon-plonky3` full parsed verify)
//!
//! Run (recommended): `RUSTFLAGS='-C target-cpu=native' cargo run -p falcon-sig-bench --release`
//!
//! Verifier lines split **native derivation / instance prep** vs **proof-system verify** so Groth16/Plonk
//! (“derive public inputs” + pairing/KZG) lines up conceptually with Plonky3 (`instance_prep` + `stark_crypto`).

use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fq;
use ark_groth16::{create_random_proof, verify_proof, Groth16, PreparedVerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use falcon_plonk::falcon_opt::FalconNTTVerificationWitness;
use falcon_plonky3::{
    prove_falcon_parsed_verify, prove_falcon_parsed_verify_single_stark,
    verify_falcon_parsed_verify, verify_falcon_parsed_verify_single_stark,
};
use falcon_r1cs::FalconNTTVerificationCircuit;
use falcon_rust::{KeyPair, NTTPolynomial, Polynomial, Signature};
use jf_plonk::{
    circuit::{Arithmetization, Circuit, PlonkCircuit},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

fn gen_sig_plonk_ok() -> (KeyPair, Signature) {
    let message = b"testing message";
    loop {
        let keypair = KeyPair::keygen();
        let sig = keypair
            .secret_key
            .sign_with_seed(b"test seed".as_ref(), message.as_ref());
        assert!(keypair.public_key.verify(message.as_ref(), &sig));

        let pk_poly: Polynomial = (&keypair.public_key).into();
        let sig_poly: Polynomial = (&sig).into();
        let hm = Polynomial::from_hash_of_message(message.as_ref(), sig.nonce());
        let uh = sig_poly * pk_poly;
        let v = hm - uh;
        if v.infinity_norm() > 765 || sig_poly.infinity_norm() > 765 {
            continue;
        }
        return (keypair, sig);
    }
}

fn groth16_public_inputs(
    pk: &falcon_rust::PublicKey,
    msg: &[u8],
    sig: &falcon_rust::Signature,
) -> Vec<Fr> {
    let pk_poly = Polynomial::from(pk);
    let pk_ntt = NTTPolynomial::from(&pk_poly);
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let hm_ntt = NTTPolynomial::from(&hm);
    let mut public_inputs = Vec::new();
    for e in pk_ntt.coeff() {
        public_inputs.push(Fr::from(*e));
    }
    for e in hm_ntt.coeff() {
        public_inputs.push(Fr::from(*e));
    }
    public_inputs
}

fn main() -> Result<(), PlonkError> {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let message = b"testing message";
    let (keypair, sig) = gen_sig_plonk_ok();

    println!("=== Falcon signature proof comparison (release, same msg/sig) ===\n");

    // --- Plonky3 ---
    let t0 = Instant::now();
    let bundle = prove_falcon_parsed_verify(&keypair.public_key, message.as_ref(), &sig);
    let p3_prove = t0.elapsed();

    let t0 = Instant::now();
    verify_falcon_parsed_verify(&keypair.public_key, message.as_ref(), &sig, &bundle).unwrap();
    let p3_verify = t0.elapsed();
    println!(
        "Plonky3 (full parsed-verify bundle): prove {:>10.2?}  verify {:>10.2?}",
        p3_prove, p3_verify
    );
    println!(
        "  (verify runs 7 subproof checks in parallel; sequential profiling split: falcon_plonky3::verify_falcon_parsed_verify_with_breakdown)"
    );

    let t0 = Instant::now();
    let single = prove_falcon_parsed_verify_single_stark(&keypair.public_key, message.as_ref(), &sig);
    let p3_single_prove = t0.elapsed();

    let t0 = Instant::now();
    match verify_falcon_parsed_verify_single_stark(&keypair.public_key, message.as_ref(), &sig, &single)
    {
        Ok(()) => {}
        Err(e) => {
            println!(
                "  note: unified single-STARK verify failed (experimental): {e:?}"
            );
        }
    }
    let p3_single_verify = t0.elapsed();
    println!(
        "Plonky3 (unified single-STARK parsed-verify): prove {:>10.2?}  verify {:>10.2?}",
        p3_single_prove, p3_single_verify
    );

    // --- Groth16 ---
    let t0 = Instant::now();
    let cs_input = FalconNTTVerificationCircuit::build_circuit(
        keypair.public_key,
        message.to_vec(),
        sig.clone(),
    );
    let r1cs_circuit = t0.elapsed();

    let t0 = Instant::now();
    let (pp, vk) = Groth16::<Bls12_381>::circuit_specific_setup(cs_input.clone(), &mut rng).unwrap();
    let r1cs_setup = t0.elapsed();

    let t0 = Instant::now();
    let proof = create_random_proof(cs_input, &pp, &mut rng).unwrap();
    let r1cs_prove = t0.elapsed();

    let t0 = Instant::now();
    let public_inputs = groth16_public_inputs(&keypair.public_key, message.as_ref(), &sig);
    let r1cs_derive_public = t0.elapsed();

    let pvk = PreparedVerifyingKey::from(vk);
    let t0 = Instant::now();
    assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
    let r1cs_verify_crypto = t0.elapsed();

    println!(
        "Groth16 / R1CS: build circuit {:>10.2?}  setup {:>10.2?}  prove {:>10.2?}",
        r1cs_circuit, r1cs_setup, r1cs_prove
    );
    println!(
        "  verify total {:>10.2?}  (= derive public_inputs {:>10.2?}  +  pairing verify {:>10.2?})",
        r1cs_derive_public + r1cs_verify_crypto,
        r1cs_derive_public,
        r1cs_verify_crypto
    );

    // --- Plonk (jellyfish) ---
    let mut cs = PlonkCircuit::<Fq>::new_ultra_plonk(8);
    let witness = FalconNTTVerificationWitness::build_witness(
        keypair.public_key,
        message.to_vec(),
        sig.clone(),
    );
    let t0 = Instant::now();
    witness.verification_circuit(&mut cs)?;
    let plonk_circuit = t0.elapsed();

    let t0 = Instant::now();
    let mut public_inputs_fq = vec![];
    let pk_poly = Polynomial::from(&keypair.public_key);
    let pk_ntt = NTTPolynomial::from(&pk_poly);
    for &e in pk_ntt.coeff() {
        public_inputs_fq.push(Fq::from(e));
    }
    let hm = Polynomial::from_hash_of_message(message.as_ref(), sig.nonce());
    let hm_ntt = NTTPolynomial::from(&hm);
    for &e in hm_ntt.coeff() {
        public_inputs_fq.push(Fq::from(e));
    }
    let plonk_derive_public = t0.elapsed();

    assert!(cs
        .check_circuit_satisfiability(&public_inputs_fq)
        .is_ok());

    let t0 = Instant::now();
    cs.finalize_for_arithmetization()?;
    let plonk_finalize = t0.elapsed();

    let srs_size = cs.srs_size()?;
    let t0 = Instant::now();
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;
    let plonk_universal_setup = t0.elapsed();

    let t0 = Instant::now();
    let (pk_plonk, vk_plonk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &cs)?;
    let plonk_preprocess = t0.elapsed();

    let t0 = Instant::now();
    let plonk_proof = PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(
        &mut rng,
        &cs,
        &pk_plonk,
        None,
    )?;
    let plonk_prove = t0.elapsed();

    let public_inputs = cs.public_input()?;
    let t0 = Instant::now();
    assert!(PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(
        &vk_plonk,
        &public_inputs,
        &plonk_proof,
        None,
    )
    .is_ok());
    let plonk_verify_crypto = t0.elapsed();

    println!(
        "Plonk (UltraPlonk+KZG): circuit {:>10.2?}  finalize {:>8.2?}  universal_setup {:>8.2?}  preprocess {:>8.2?}  prove {:>10.2?}",
        plonk_circuit,
        plonk_finalize,
        plonk_universal_setup,
        plonk_preprocess,
        plonk_prove
    );
    println!(
        "  verify total {:>10.2?}  (= derive bindings {:>10.2?}  +  KZG verify {:>10.2?})",
        plonk_derive_public + plonk_verify_crypto,
        plonk_derive_public,
        plonk_verify_crypto
    );

    println!(
        "\nNotes:\n\
        - Groth16/Plonk verify lines split derive-public vs pairing/KZG; Plonky3 bundle verify is parallel over 7 STARKs.\n\
        - Unified single-STARK verify runs one PCS/STARK pipeline (printed above).\n\
        - Sequential component timings for Plonky3 bundle: `verify_falcon_parsed_verify_with_breakdown` (see README).\n\
        - Statements differ (norm bounds, single SNARK vs bundle); timings are not proof equivalence."
    );

    Ok(())
}
