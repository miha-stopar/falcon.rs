//! Falcon **L² bound** check in the coefficient domain (parsed dual limbs), matching
//! [`DualPolynomial::l2_norm`] + [`Polynomial::l2_norm`] in [`verify_parsed_sig`].
//!
//! One row per contribution in the order
//! `sig_pos[0..N)`, `sig_neg[0..N)`, `v_pos[0..N)`, `v_neg[0..N)` (total `4 * N` rows).
//! Accumulates `m²` where `m` is the centered magnitude mod `q` (same rule as `falcon-rust`).
//!
//! Uses a two-row window for the running sum and **low-degree** constraints:
//! - `e + delta_q = q - 1` with bit witnesses proves `e < q` without a high-degree OR;
//! - `is_high` + `slack` prove the split `e ≤ 6144` vs `e ≥ 6145` for centering.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::{MODULUS, MODULUS_MINUS_1_OVER_TWO, N, SIG_L2_BOUND};

use super::dual_ntt_equation::QUOT_BITS;

/// Preprocessed columns: verifier-rebuilt expected coefficient magnitude `e` per row.
pub const NUM_PREPROCESSED_COLS: usize = 1;

/// Bits for `delta_q` in `e + delta_q = q - 1` (proves `e ≤ q - 1`).
pub const DELTA_Q_BITS: usize = QUOT_BITS;
/// Slack magnitude: `≤ 6144` fits in 14 bits.
pub const SLACK_BITS: usize = QUOT_BITS;
/// Upper bound on accumulated `Σ m²` (`SIG_L2_BOUND < 2^27` for both Falcon parameter sets).
pub const ACCUM_BITS: usize = 27;
/// Witness for `SIG_L2_BOUND - accum` on the last row (non-last rows force `0`).
pub const BOUND_DIFF_BITS: usize = ACCUM_BITS;

pub const NUM_MAIN_COLS: usize =
    QUOT_BITS + DELTA_Q_BITS + 1 + SLACK_BITS + ACCUM_BITS + BOUND_DIFF_BITS;

const Q_MINUS_1_U32: u32 = MODULUS as u32 - 1;
pub(crate) const SIG_BOUND_U32: u32 = SIG_L2_BOUND as u32;

#[repr(C)]
pub struct MainRow<F> {
    pub coeff_bits: [F; QUOT_BITS],
    pub delta_q_bits: [F; DELTA_Q_BITS],
    pub is_high: F,
    pub slack_bits: [F; SLACK_BITS],
    pub accum_bits: [F; ACCUM_BITS],
    pub bound_diff_bits: [F; BOUND_DIFF_BITS],
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
pub struct FalconL2BoundAir {
    /// Verifier-rebuilt expected coefficient `e` per row (`4N × 1`). Binds the L² witness to the
    /// actual `sig`/`v` coefficients of the statement, so a prover cannot satisfy the norm bound
    /// with unrelated (e.g. all-zero) coefficients.
    coeff_ref: RowMajorMatrix<KoalaBear>,
}

impl BaseAir<KoalaBear> for FalconL2BoundAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.coeff_ref.clone())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..NUM_MAIN_COLS).collect()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Only the current row's reference coefficient is used.
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Let uni-stark infer the exact symbolic degree (transition × `m²` crosses degree 6).
        None
    }
}

fn bits_to_expr<AB: AirBuilder<F = KoalaBear>>(bits: &[AB::Var]) -> AB::Expr {
    let mut acc: AB::Expr = KoalaBear::ZERO.into();
    for (i, bit) in bits.iter().enumerate() {
        let coeff = KoalaBear::from_u32(1u32 << i);
        acc = acc + (*bit).into() * coeff;
    }
    acc
}

pub(crate) fn falcon_l2_contrib<AB: AirBuilder<F = KoalaBear>>(cur: &MainRow<AB::Var>) -> AB::Expr {
    let e = bits_to_expr::<AB>(&cur.coeff_bits);
    let is_h: AB::Expr = cur.is_high.into();
    let q_embed: AB::Expr = KoalaBear::from_u32(MODULUS as u32).into();
    let two: AB::Expr = KoalaBear::from_u32(2u32).into();
    // m = e + is_high * (q - 2*e); contrib = m²
    let m_expr = e.clone() + is_h * (q_embed - two * e);
    m_expr.clone() * m_expr
}

/// Per-row constraints (no `next` row): boolean decomposition, `e + delta_q = q - 1`, slack split.
fn eval_common_shared<AB: AirBuilder<F = KoalaBear>>(builder: &mut AB) {
    let main_win = builder.main();
    let cur: &MainRow<AB::Var> = main_win.current_slice().borrow();

    builder.assert_bools(cur.coeff_bits);
    builder.assert_bools(cur.delta_q_bits);
    builder.assert_bool(cur.is_high);
    builder.assert_bools(cur.slack_bits);
    builder.assert_bools(cur.accum_bits);
    builder.assert_bools(cur.bound_diff_bits);

    // Bind the reconstructed coefficient `e` to the verifier-rebuilt reference (preprocessed),
    // so the squared-norm accumulation is over the *actual* `sig`/`v` coefficients.
    let coeff_ref = builder.preprocessed().current_slice()[0];

    let e = bits_to_expr::<AB>(&cur.coeff_bits);
    builder.assert_zero(e.clone() - coeff_ref.into());

    let delta_q = bits_to_expr::<AB>(&cur.delta_q_bits);
    let qm1: AB::Expr = KoalaBear::from_u32(Q_MINUS_1_U32).into();
    builder.assert_zero(e.clone() + delta_q - qm1);

    let slack = bits_to_expr::<AB>(&cur.slack_bits);
    let is_h: AB::Expr = cur.is_high.into();
    let one: AB::Expr = KoalaBear::ONE.into();
    let c6144: AB::Expr = KoalaBear::from_u32(MODULUS_MINUS_1_OVER_TWO as u32).into();
    let c6145: AB::Expr = KoalaBear::from_u32(MODULUS_MINUS_1_OVER_TWO as u32 + 1).into();
    // (1 - is_high) * (e + slack - 6144) + is_high * (e - 6145 - slack) = 0
    let branch_lo = (one.clone() - is_h.clone()) * (e.clone() + slack.clone() - c6144);
    let branch_hi = is_h * (e.clone() - c6145 - slack);
    builder.assert_zero(branch_lo + branch_hi);
}

fn eval_first_accum_only<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let main_win = b.main();
    let cur: &MainRow<AB::Var> = main_win.current_slice().borrow();
    let accum = bits_to_expr::<AB>(&cur.accum_bits);
    let contrib = falcon_l2_contrib::<AB>(cur);
    b.assert_zero(accum - contrib);
    let diff = bits_to_expr::<AB>(&cur.bound_diff_bits);
    b.assert_zero(diff);
}

fn eval_mid_transition<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let main_win = b.main();
    let cur: &MainRow<AB::Var> = main_win.current_slice().borrow();
    let next: &MainRow<AB::Var> = main_win.next_slice().borrow();

    let cur_accum = bits_to_expr::<AB>(&cur.accum_bits);
    let next_accum = bits_to_expr::<AB>(&next.accum_bits);
    let next_contrib = falcon_l2_contrib::<AB>(next);
    b.assert_zero(next_accum - cur_accum - next_contrib);

    let cur_diff = bits_to_expr::<AB>(&cur.bound_diff_bits);
    b.assert_zero(cur_diff);
}

fn eval_last_bound_only<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let main_win = b.main();
    let cur: &MainRow<AB::Var> = main_win.current_slice().borrow();
    let accum = bits_to_expr::<AB>(&cur.accum_bits);
    let diff = bits_to_expr::<AB>(&cur.bound_diff_bits);
    let bound: AB::Expr = KoalaBear::from_u32(SIG_BOUND_U32).into();
    b.assert_zero(accum + diff - bound);
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconL2BoundAir {
    fn eval(&self, builder: &mut AB) {
        eval_common_shared(builder);

        let mut first = builder.when_first_row();
        eval_first_accum_only(&mut first);

        // All non-last rows (including row 0): link `accum` to the next row's contribution.
        let mut mid = builder.when_transition();
        eval_mid_transition(&mut mid);

        let mut last = builder.when_last_row();
        eval_last_bound_only(&mut last);
    }
}

impl FalconL2BoundAir {
    /// `coeff_ref` must be `4N × `[`NUM_PREPROCESSED_COLS`]: the verifier-rebuilt expected
    /// coefficient `e` per row, in the row order `sig_pos`, `sig_neg`, `v_pos`, `v_neg`.
    pub fn new(coeff_ref: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(
            coeff_ref.width(),
            NUM_PREPROCESSED_COLS,
            "coeff_ref width must be NUM_PREPROCESSED_COLS"
        );
        assert_eq!(
            coeff_ref.height(),
            4 * N,
            "coeff_ref height must be 4*N (one row per accumulated coefficient)"
        );
        Self { coeff_ref }
    }

    pub fn coeff_ref(&self) -> &RowMajorMatrix<KoalaBear> {
        &self.coeff_ref
    }
}
