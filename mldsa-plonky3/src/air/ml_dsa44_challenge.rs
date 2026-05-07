//! ML-DSA-44: constrain equality of the 32-byte verification challenge (`c_tilde`) with the
//! recomputed value (witness), one byte per row.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_koala_bear::KoalaBear;

/// Challenge length in bytes for ML-DSA-44 (`Lambda` in FIPS 204).
pub const MLDSA44_LAMBDA_BYTES: usize = 32;

pub const NUM_MAIN_COLS: usize = 2;

#[repr(C)]
pub struct ChallengeRow<F> {
    pub c_tilde_byte: F,
    pub recomputed_byte: F,
}

impl<F> Borrow<ChallengeRow<F>> for [F] {
    fn borrow(&self) -> &ChallengeRow<F> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ChallengeRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

#[derive(Clone, Debug, Default)]
pub struct MlDsa44ChallengeBytesAir;

impl BaseAir<KoalaBear> for MlDsa44ChallengeBytesAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

fn eval_row<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let main_win = b.main();
    let row: &ChallengeRow<AB::Var> = main_win.current_slice().borrow();
    b.assert_eq(row.c_tilde_byte, row.recomputed_byte);
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for MlDsa44ChallengeBytesAir {
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_row(&mut t);

        let mut last = builder.when_last_row();
        eval_row(&mut last);
    }
}
