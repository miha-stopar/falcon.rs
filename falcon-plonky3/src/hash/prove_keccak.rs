//! Prove Falcon SHAKE256 Keccak-f permutations with [`p3_keccak_air`].

use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{prove, Proof, StarkGenericConfig};

use crate::air::StatementBoundAir;
use crate::config::{FalconStarkConfig, FalconStarkZkConfig};
use crate::full_verify::FALCON_STATEMENT_DIGEST_LEN;
use crate::hash::HashToPointResult;

macro_rules! impl_prove_shake_keccak {
    ($sc:ty, $fn:ident) => {
        /// STARK proving every `process_block` step in a Falcon SHAKE256 expansion.
        pub fn $fn(
            config: &$sc,
            result: &HashToPointResult,
            digest: &[KoalaBear; FALCON_STATEMENT_DIGEST_LEN],
        ) -> Proof<$sc> {
            let inputs = result.keccak_inputs.clone();
            let trace = generate_trace_rows::<KoalaBear>(inputs, 0);
            let air = StatementBoundAir::new(KeccakAir {}, FALCON_STATEMENT_DIGEST_LEN);
            prove(config, &air, trace, digest)
        }
    };
}

impl_prove_shake_keccak!(FalconStarkConfig, prove_shake_keccak);
impl_prove_shake_keccak!(FalconStarkZkConfig, prove_shake_keccak_zk);
