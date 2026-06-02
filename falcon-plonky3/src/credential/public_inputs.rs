//! Public inputs for a credential presentation (known to the verifier).

use falcon_rust::{Polynomial, PublicKey, Signature};

/// Data the verifier knows when checking a credential proof.
///
/// ## `hm` (message hash polynomial)
///
/// Native Falcon uses `hm = H(msg, sig.nonce())`. Phase C proves this in-circuit: the
/// **hash-to-point** and **SHAKE/Keccak** sub-proofs bind `hm` to `(msg, nonce)` with the
/// nonce only in the private witness. The verifier sees `hm` coefficients as public outputs of
/// the hash-to-point STARK (`public_values`).
#[derive(Clone, Debug)]
pub struct FalconCredentialPublicInputs<'a> {
    /// Issuer public key (Falcon signing key).
    pub issuer_pk: &'a PublicKey,
    /// Message / policy context bytes (attribute commitment, verifier challenge prefix, etc.).
    pub msg: &'a [u8],
    /// Public `hm` coefficients (outputs of in-circuit hash-to-point).
    pub hm: Polynomial,
}

impl<'a> FalconCredentialPublicInputs<'a> {
    /// Build public inputs from a presentation (uses native hash for `hm`; prover must match in-circuit).
    pub fn from_presentation(issuer_pk: &'a PublicKey, msg: &'a [u8], sig: &Signature) -> Self {
        let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
        Self {
            issuer_pk,
            msg,
            hm,
        }
    }
}
