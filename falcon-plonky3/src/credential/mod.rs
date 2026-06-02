//! ZK credential verification API (OpenAC / Vega style): **fixed verification keys**, public
//! issuer/message inputs, **private** Falcon signature witness.
//!
//! See [`../docs/zk_credential.md`](../docs/zk_credential.md) for architecture and roadmap.

mod keys;
mod prove;
mod public_inputs;

pub use keys::FalconCredentialVerifyKeys;
pub use prove::{prove_credential, verify_credential, FalconCredentialProof};
pub use public_inputs::FalconCredentialPublicInputs;
