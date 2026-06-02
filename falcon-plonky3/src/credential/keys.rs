//! One-time setup of **reusable** preprocessed verification keys (circuit-fixed columns only).

use p3_uni_stark::{
    setup_preprocessed, PreprocessedProverData, PreprocessedVerifierKey, StarkGenericConfig,
};
use p3_util::log2_strict_usize;

use crate::air::{FalconNttFullAir, StatementBoundAir};
use crate::config::{FalconStarkConfig, FalconStarkZkConfig};
use crate::full_verify::FALCON_STATEMENT_DIGEST_LEN;
use falcon_rust::N;

/// Reusable verification keys for the credential bundle (fixed for Falcon parameter set `N`).
pub struct FalconCredentialVerifyKeys<SC: StarkGenericConfig> {
    pub ntt_full_pp: PreprocessedProverData<SC>,
    pub ntt_full_vk: PreprocessedVerifierKey<SC>,
    pub coeff_dual_pp: Option<PreprocessedProverData<SC>>,
    pub coeff_dual_vk: Option<PreprocessedVerifierKey<SC>>,
    pub ntt_degree_bits: usize,
    pub dual_degree_bits: usize,
    pub coeff_degree_bits: usize,
    pub l2_degree_bits: usize,
}

macro_rules! impl_credential_keys_setup {
    ($sc:ty) => {
        impl FalconCredentialVerifyKeys<$sc> {
            pub fn setup(config: &$sc) -> Self {
                let ntt_degree_bits = log2_strict_usize(ntt_full_trace_height());
                let ntt_air = StatementBoundAir::new(
                    FalconNttFullAir::new_universal(),
                    FALCON_STATEMENT_DIGEST_LEN,
                );
                let (ntt_full_pp, ntt_full_vk) = setup_preprocessed(config, &ntt_air, ntt_degree_bits)
                    .expect("ntt_full universal setup");

                Self {
                    ntt_full_pp,
                    ntt_full_vk,
                    coeff_dual_pp: None,
                    coeff_dual_vk: None,
                    ntt_degree_bits,
                    dual_degree_bits: log2_strict_usize(N),
                    coeff_degree_bits: log2_strict_usize(N),
                    l2_degree_bits: log2_strict_usize(4 * N),
                }
            }
        }
    };
}

impl_credential_keys_setup!(FalconStarkConfig);
impl_credential_keys_setup!(FalconStarkZkConfig);

fn ntt_full_trace_height() -> usize {
    use crate::air::ntt_full_trace_height;
    ntt_full_trace_height()
}
