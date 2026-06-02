//! One-time setup of **reusable** preprocessed verification keys (circuit-fixed columns only).

use p3_uni_stark::{setup_preprocessed, PreprocessedProverData, PreprocessedVerifierKey};
use p3_util::log2_strict_usize;

use crate::air::{FalconNttFullAir, StatementBoundAir};
use crate::config::FalconStarkConfig;
use crate::full_verify::FALCON_STATEMENT_DIGEST_LEN;
use falcon_rust::N;

/// Reusable verification keys for the credential bundle (fixed for Falcon parameter set `N`).
///
/// Sub-proofs without universal preprocessed columns (`dual_ntt`, `l2`) store `None` here;
/// their `Air` instances still depend on public periodic data derived from
/// [`super::public_inputs::FalconCredentialPublicInputs`].
pub struct FalconCredentialVerifyKeys {
    pub ntt_full_pp: PreprocessedProverData<FalconStarkConfig>,
    pub ntt_full_vk: PreprocessedVerifierKey<FalconStarkConfig>,
    pub coeff_dual_pp: Option<PreprocessedProverData<FalconStarkConfig>>,
    pub coeff_dual_vk: Option<PreprocessedVerifierKey<FalconStarkConfig>>,
    pub ntt_degree_bits: usize,
    pub dual_degree_bits: usize,
    pub coeff_degree_bits: usize,
    pub l2_degree_bits: usize,
}

impl FalconCredentialVerifyKeys {
    /// Commit universal preprocessed columns once (NTT twiddles + active selectors; coeff AIR has none).
    pub fn setup(config: &FalconStarkConfig) -> Self {
        let ntt_degree_bits = log2_strict_usize(ntt_full_trace_height());
        let ntt_air =
            StatementBoundAir::new(FalconNttFullAir::new_universal(), FALCON_STATEMENT_DIGEST_LEN);
        let (ntt_full_pp, ntt_full_vk) =
            setup_preprocessed(config, &ntt_air, ntt_degree_bits).expect("ntt_full universal setup");

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

fn ntt_full_trace_height() -> usize {
    use crate::air::ntt_full_trace_height;
    ntt_full_trace_height()
}
