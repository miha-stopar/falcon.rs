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
//! **Soundness:** operands are reconstructed from **14 boolean bits** each, so
//! `0 ≤ pos, neg ≤ 2^14 - 1` and `pos * neg < 2^28 < p_KoalaBear`; field multiplication
//! matches integer multiplication, so `pos * neg = 0` is exact.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use super::dual_ntt_equation::QUOT_BITS;

pub const NUM_MAIN_COLS: usize = 2 * QUOT_BITS;

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

/// AIR: one row per coefficient index `i ∈ [0, N)`; enforces `sig_pos[i] * sig_neg[i] = 0`.
#[derive(Clone, Debug, Default)]
pub struct FalconCoeffDualProductZeroAir;

impl BaseAir<KoalaBear> for FalconCoeffDualProductZeroAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn eval_row_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
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
    pub fn new() -> Self {
        Self
    }
}
