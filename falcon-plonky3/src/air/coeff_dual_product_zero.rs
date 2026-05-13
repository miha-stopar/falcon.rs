//! Per-coefficient constraint **`sig_pos[i] * sig_neg[i] = 0`** for the dual limb
//! decomposition used in parsed Falcon verification ([`verify_parsed_sig`]).
//!
//! [`verify_parsed_sig`]: falcon_rust::PublicKey::verify_parsed_sig
//!
//! In [`DualPolynomial`], each coefficient is split so that at most one of `pos` / `neg`
//! is nonzero ([`DualPolynomial::from`]), hence the pointwise product vanishes. This AIR
//! enforces that structure in the **coefficient domain** (not NTT); it is complementary
//! to [`super::dual_ntt_equation::FalconDualNttEquationAir`], which reasons in NTT domain.
//!
//! **Preprocessed** columns fix the verifier’s expected `sig_pos[i]`, `sig_neg[i]` (embedded
//! mod-`q` residues). The main trace’s bit reconstructions must match them, so the product
//! constraint applies to the **statement** coefficients, not an unconstrained bit split.
//!
//! **Soundness:** operands are reconstructed from **14 boolean bits** each, so
//! `0 ≤ pos, neg ≤ 2^14 - 1` and `pos * neg < 2^28 < p_KoalaBear`; field multiplication
//! matches integer multiplication, so `pos * neg = 0` is exact.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::N;

use super::dual_ntt_equation::QUOT_BITS;

pub const NUM_PREPROCESSED_COLS: usize = 2;

pub const NUM_MAIN_COLS: usize = 2 * QUOT_BITS;

#[repr(C)]
pub struct PreprocessedRow<F> {
    pub exp_sig_pos: F,
    pub exp_sig_neg: F,
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

#[repr(C)]
pub struct MainRow<F> {
    pub sig_pos_bits: [F; QUOT_BITS],
    pub sig_neg_bits: [F; QUOT_BITS],
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

/// AIR: one row per coefficient index `i ∈ [0, N)`; enforces `sig_pos[i] * sig_neg[i] = 0`
/// and equality of bit-decomposed limbs to preprocessed expected coefficients.
#[derive(Clone, Debug)]
pub struct FalconCoeffDualProductZeroAir {
    expected: RowMajorMatrix<KoalaBear>,
}

impl BaseAir<KoalaBear> for FalconCoeffDualProductZeroAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.expected.clone())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn eval_row_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let (exp_pos, exp_neg) = {
        let prep: &PreprocessedRow<AB::Var> = b.preprocessed().current_slice().borrow();
        (prep.exp_sig_pos, prep.exp_sig_neg)
    };

    let main_win = b.main();
    let m: &MainRow<AB::Var> = main_win.current_slice().borrow();

    for bit in m.sig_pos_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.sig_neg_bits.iter().copied() {
        b.assert_bool(bit);
    }

    let mut sig_pos: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        sig_pos = sig_pos + m.sig_pos_bits[i].into() * coeff;
    }
    let mut sig_neg: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        sig_neg = sig_neg + m.sig_neg_bits[i].into() * coeff;
    }

    b.assert_eq(sig_pos.clone(), exp_pos.into());
    b.assert_eq(sig_neg.clone(), exp_neg.into());
    b.assert_zero(sig_pos * sig_neg);
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconCoeffDualProductZeroAir {
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_row_constraints(&mut t);

        let mut last = builder.when_last_row();
        eval_row_constraints(&mut last);
    }
}

impl FalconCoeffDualProductZeroAir {
    /// `expected` must be `N × 2`: columns are KoalaBear-embedded expected `sig_pos`, `sig_neg`
    /// coefficients per row (same table the verifier builds from the signature).
    pub fn new(expected: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(
            expected.height(),
            N,
            "expected height must be N (one row per coefficient index)"
        );
        assert_eq!(expected.width(), NUM_PREPROCESSED_COLS);
        Self { expected }
    }
}
