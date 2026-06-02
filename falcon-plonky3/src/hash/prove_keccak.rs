//! Prove Falcon SHAKE256 Keccak-f permutations with [`p3_keccak_air`].

use p3_field::PrimeField64;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{prove, Proof, StarkGenericConfig};

use crate::air::StatementBoundAir;
use crate::config::FalconStarkConfig;
use crate::full_verify::FALCON_STATEMENT_DIGEST_LEN;
use crate::hash::HashToPointResult;

/// STARK proving every `process_block` step in a Falcon SHAKE256 expansion.
pub fn prove_shake_keccak(
    config: &FalconStarkConfig,
    result: &HashToPointResult,
    digest: &[KoalaBear; FALCON_STATEMENT_DIGEST_LEN],
) -> Proof<FalconStarkConfig> {
    let inputs = result.keccak_inputs.clone();
    let trace = generate_trace_rows::<KoalaBear>(inputs, 0);
    let air = StatementBoundAir::new(KeccakAir {}, FALCON_STATEMENT_DIGEST_LEN);
    prove(config, &air, trace, digest)
}
