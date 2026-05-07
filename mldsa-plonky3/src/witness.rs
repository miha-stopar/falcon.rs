use ml_dsa::{MlDsa44, Signature, VerifyingKey};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{MlDsa44ChallengeBytesAir, MLDSA44_LAMBDA_BYTES};

#[inline]
fn fe_byte(b: u8) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(u32::from(b))
}

/// Build the main trace for [`MlDsa44ChallengeBytesAir`]: row `i` holds `c_tilde[i]` and the
/// recomputed challenge byte from [`VerifyingKey::recomputed_challenge_bytes`].
///
/// # Panics
///
/// Debug-build panic if `sig` does not match `vk` / `msg` (mismatch would make the STARK unsatisfiable).
pub fn build_ml_dsa44_challenge_trace(
    vk: &VerifyingKey<MlDsa44>,
    msg: &[u8],
    sig: &Signature<MlDsa44>,
) -> RowMajorMatrix<KoalaBear> {
    let mu = vk.mu_for_verify_internal(msg);
    let recomputed = vk.recomputed_challenge_bytes(&mu, sig);
    let c = sig.c_tilde();

    debug_assert_eq!(
        c.as_slice(),
        recomputed.as_slice(),
        "signature must verify under ML-DSA.Verify_internal for this witness"
    );

    let mut vals = Vec::with_capacity(MLDSA44_LAMBDA_BYTES * crate::air::NUM_MAIN_COLS);
    for i in 0..MLDSA44_LAMBDA_BYTES {
        vals.push(fe_byte(c[i]));
        vals.push(fe_byte(recomputed[i]));
    }

    RowMajorMatrix::new(vals, crate::air::NUM_MAIN_COLS)
}

/// Convenience: air struct is stateless for this bootstrap AIR.
pub fn challenge_air() -> MlDsa44ChallengeBytesAir {
    MlDsa44ChallengeBytesAir
}
