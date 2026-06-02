//! ZK credential verification API (OpenAC / Vega style): **fixed verification keys**, public
//! issuer/message inputs, **private** Falcon signature witness.
//!
//! See [`../docs/zk_credential.md`](../docs/zk_credential.md) for architecture and roadmap.

mod keys;
mod prove;
mod public_inputs;

pub use keys::FalconCredentialVerifyKeys;
pub use crate::config::FalconStarkZkConfig;
pub use prove::{
    falcon_credential_verify_digest, prove_credential, prove_credential_zk, verify_credential,
    verify_credential_zk, CredentialProofBundle, FalconCredentialProof, FalconCredentialZkProof,
};
pub use public_inputs::FalconCredentialPublicInputs;
