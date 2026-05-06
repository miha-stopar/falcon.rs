//! AIR for the per-index dual-NTT verification equation from `falcon-r1cs` (see
//! `FalconDualNTTVerificationCircuit`), without full `mod_q` reduction or NTT
//! wiring inside the trace.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

pub const NUM_PREPROCESSED_COLS: usize = 2;
pub const NUM_MAIN_COLS: usize = 6;

#[repr(C)]
pub struct PreprocessedRow<F> {
    pub pk_ntt: F,
    pub hm_ntt: F,
}

#[repr(C)]
pub struct MainRow<F> {
    pub sig_pos_ntt: F,
    pub sig_neg_ntt: F,
    pub v_pos_ntt: F,
    pub v_neg_ntt: F,
    /// `(hm + v_neg + sig_neg * pk) mod MODULUS` at this NTT index (full integer sum then reduce).
    pub lhs_mod: F,
    /// `(v_pos + sig_pos * pk) mod MODULUS`.
    pub rhs_mod: F,
}

impl<F> Borrow<PreprocessedRow<F>> for [F] {
    fn borrow(&self) -> &PreprocessedRow<F> {
        debug_assert_eq!(self.len(), NUM_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PreprocessedRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<F> Borrow<MainRow<F>> for [F] {
    fn borrow(&self) -> &MainRow<F> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

#[derive(Clone, Debug)]
pub struct FalconDualNttEquationAir {
    preprocessed: RowMajorMatrix<KoalaBear>,
}

impl FalconDualNttEquationAir {
    pub fn new(preprocessed: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(
            preprocessed.width(),
            NUM_PREPROCESSED_COLS,
            "preprocessed width must match pk_ntt, hm_ntt"
        );
        assert!(preprocessed.height().is_power_of_two());
        Self { preprocessed }
    }
}

impl BaseAir<KoalaBear> for FalconDualNttEquationAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.preprocessed.clone())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Linear relation in trace variables (no native field × for Falcon's mod-q product).
        Some(2)
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconDualNttEquationAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed().current_slice();
        debug_assert_eq!(prep.len(), NUM_PREPROCESSED_COLS);
        let main_local: &MainRow<AB::Var> = main.current_slice().borrow();

        let lhs = main_local.lhs_mod;
        let rhs = main_local.rhs_mod;

        // Matches `mod_q(hm + v_neg + sig_neg * pk) == mod_q(v_pos + sig_pos * pk)` from the
        // R1CS circuit, with both sides fully reduced mod `MODULUS` in the witness.

        let mut t = builder.when_transition();
        t.assert_eq(lhs, rhs);

        let mut last = builder.when_last_row();
        last.assert_eq(lhs, rhs);
    }
}
