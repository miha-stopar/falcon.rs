//! **Experimental** single-STARK Falcon parsed-verify AIR: stacks dual-NTT + coeff dual-zero,
//! L² accumulation, and four full-NTT limbs in **one** trace (segment selectors in preprocessed columns).
//!
//! The default [`crate::full_verify::prove_falcon_parsed_verify`] path keeps **seven** proofs for
//! comparison. This module trades a wider trace / higher-degree constraint blowups for **one**
//! PCS commitment pipeline.
//!
//! Dual inputs `pk_ntt`, `hm_ntt` are embedded in preprocessed columns (`row ↦ row % N`) instead of
//! Plonky3 periodic columns, so the constraint graph stays standard preprocessed + main only.

use core::borrow::Borrow;

use p3_air::{
    Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::{MODULUS, MODULUS_MINUS_1_OVER_TWO, N};

use super::dual_ntt_equation::{
    DualNttPreprocessedRow, MainRow as DualMainRow, NUM_DUAL_NTT_PREPROCESSED_COLS, QUOT_BITS,
};
use super::coeff_dual_product_zero::{
    MainRow as CoeffMainRow, PreprocessedRow as CoeffPrepRow, NUM_MAIN_COLS as COEFF_MAIN_COLS,
    NUM_PREPROCESSED_COLS as COEFF_PREP_COLS,
};
use super::dual_ntt_equation::NUM_MAIN_COLS as DUAL_MAIN_COLS;
use super::l2_bound::{
    MainRow as L2MainRow, NUM_MAIN_COLS as L2_MAIN_COLS,
};
use super::l2_bound::{falcon_l2_contrib, SIG_BOUND_U32};
use super::ntt_full::{
    MainFullRow as NttMainRow, PreprocessedFullRow as NttPrepRow, NUM_MAIN_COLS as NTT_MAIN_COLS,
    NUM_PREPROCESSED_COLS as NTT_PREP_COLS, ntt_full_trace_height,
};

/// One-hot segment: dual+coeff (`[1,0,0]`), L² (`[0,1,0]`), NTT butterfly (`[0,0,1]`).
pub const UNIFIED_SEG_BITS: usize = 3;
pub const UNIFIED_PREP_PAD_BEFORE_DUAL: usize = UNIFIED_SEG_BITS;
pub const UNIFIED_DUAL_PREP_OFF: usize = UNIFIED_PREP_PAD_BEFORE_DUAL;
pub const UNIFIED_COEFF_PREP_OFF: usize = UNIFIED_DUAL_PREP_OFF + NUM_DUAL_NTT_PREPROCESSED_COLS;
pub const UNIFIED_NTT_PREP_OFF: usize = UNIFIED_COEFF_PREP_OFF + COEFF_PREP_COLS;
/// Embedded periodic dual inputs (`pk_ntt`, `hm_ntt`) replicated as `row → row % N`.
pub const UNIFIED_PKHM_EMB_OFF: usize = UNIFIED_NTT_PREP_OFF + NTT_PREP_COLS;
pub const UNIFIED_PREP_WIDTH: usize = UNIFIED_PKHM_EMB_OFF + 2;

pub const UNIFIED_COEFF_MAIN_OFF: usize = DUAL_MAIN_COLS;
pub const UNIFIED_MAIN_WIDTH: usize = L2_MAIN_COLS;

pub fn unified_dual_coeff_rows() -> usize {
    N
}

pub fn unified_l2_rows() -> usize {
    4 * N
}

pub fn unified_ntt_segment_rows() -> usize {
    ntt_full_trace_height()
}

pub fn unified_ntt_total_rows() -> usize {
    4 * unified_ntt_segment_rows()
}

pub fn unified_body_rows() -> usize {
    unified_dual_coeff_rows() + unified_l2_rows() + unified_ntt_total_rows()
}

pub fn unified_trace_height() -> usize {
    unified_body_rows().next_power_of_two()
}

#[derive(Clone, Debug)]
pub struct FalconUnifiedParsedVerifyAir {
    /// Full `H × UNIFIED_PREP_WIDTH` including segment bits and embedded `pk_ntt`/`hm_ntt` columns.
    preprocessed: RowMajorMatrix<KoalaBear>,
}

impl FalconUnifiedParsedVerifyAir {
    pub fn new(preprocessed: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(preprocessed.width(), UNIFIED_PREP_WIDTH);
        assert_eq!(preprocessed.height(), unified_trace_height());
        Self { preprocessed }
    }
}

impl BaseAir<KoalaBear> for FalconUnifiedParsedVerifyAir {
    fn width(&self) -> usize {
        UNIFIED_MAIN_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.preprocessed.clone())
    }

    fn preprocessed_width(&self) -> usize {
        UNIFIED_PREP_WIDTH
    }

    fn num_periodic_columns(&self) -> usize {
        0
    }

    fn periodic_columns(&self) -> Vec<Vec<KoalaBear>> {
        Vec::new()
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..UNIFIED_MAIN_WIDTH).collect()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        (0..UNIFIED_PREP_WIDTH).collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }
}

fn eval_segment_one_hot_three_vars<AB: AirBuilder<F = KoalaBear>>(
    b: &mut FilteredAirBuilder<'_, AB>,
    seg: &[AB::Var; UNIFIED_SEG_BITS],
) {
    let s0: AB::Expr = seg[0].into();
    let s1: AB::Expr = seg[1].into();
    let s2: AB::Expr = seg[2].into();
    let one: AB::Expr = KoalaBear::ONE.into();
    b.assert_bool(seg[0]);
    b.assert_bool(seg[1]);
    b.assert_bool(seg[2]);
    b.assert_zero(s0.clone() + s1.clone() + s2.clone() - one);
    b.assert_zero(s0.clone() * s1.clone());
    b.assert_zero(s0.clone() * s2.clone());
    b.assert_zero(s1.clone() * s2.clone());
}

fn eval_dual_ntt_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let prep_full = b.preprocessed().current_slice();
    let pk: AB::Expr = prep_full[UNIFIED_PKHM_EMB_OFF].into();
    let hm: AB::Expr = prep_full[UNIFIED_PKHM_EMB_OFF + 1].into();

    let dual_prep: &DualNttPreprocessedRow<AB::Var> = prep_full[UNIFIED_DUAL_PREP_OFF..][..NUM_DUAL_NTT_PREPROCESSED_COLS]
        .borrow();

    let exp_sp = dual_prep.exp_sig_pos_ntt;
    let exp_sn = dual_prep.exp_sig_neg_ntt;
    let exp_vp = dual_prep.exp_v_pos_ntt;
    let exp_vn = dual_prep.exp_v_neg_ntt;

    let main_win = b.main();
    let row = main_win.current_slice();
    let m: &DualMainRow<AB::Var> = row[..DUAL_MAIN_COLS].borrow();

    let sig_p = m.sig_pos_ntt;
    let sig_n = m.sig_neg_ntt;
    let v_p = m.v_pos_ntt;
    let v_n = m.v_neg_ntt;
    let lhs = m.lhs_mod;
    let rhs = m.rhs_mod;
    let prod_sp = m.prod_sig_pos_pk;
    let prod_sn = m.prod_sig_neg_pk;

    b.assert_zero(sig_p.into() - exp_sp.into());
    b.assert_zero(sig_n.into() - exp_sn.into());
    b.assert_zero(v_p.into() - exp_vp.into());
    b.assert_zero(v_n.into() - exp_vn.into());

    for bit in m.quot_l_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    for bit in m.quot_r_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }

    b.assert_zero(prod_sp.into() - sig_p.into() * pk.clone());
    b.assert_zero(prod_sn.into() - sig_n.into() * pk);

    let sum_l = hm.clone() + v_n.into() + prod_sn.into();
    let sum_r = v_p.into() + prod_sp.into();
    let q_embed = KoalaBear::from_u32(u32::from(MODULUS));

    let mut quot_l: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        quot_l = quot_l + m.quot_l_bits[i].into() * coeff;
    }
    let mut quot_r: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        quot_r = quot_r + m.quot_r_bits[i].into() * coeff;
    }

    b.assert_zero(sum_l - lhs.into() - quot_l * q_embed.clone());
    b.assert_zero(sum_r - rhs.into() - quot_r * q_embed);
    b.assert_zero(lhs.into() - rhs.into());
}

fn eval_coeff_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let prep_full = b.preprocessed().current_slice();
    let coeff_prep: &CoeffPrepRow<AB::Var> = prep_full[UNIFIED_COEFF_PREP_OFF..][..COEFF_PREP_COLS].borrow();
    let exp_pos = coeff_prep.exp_sig_pos;
    let exp_neg = coeff_prep.exp_sig_neg;

    let main_win = b.main();
    let row = main_win.current_slice();
    let m: &CoeffMainRow<AB::Var> = row[UNIFIED_COEFF_MAIN_OFF..][..COEFF_MAIN_COLS].borrow();

    for bit in m.sig_pos_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    for bit in m.sig_neg_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
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

    b.assert_zero(sig_pos.clone() - exp_pos.into());
    b.assert_zero(sig_neg.clone() - exp_neg.into());
    b.assert_zero(sig_pos * sig_neg);
}

fn bits_to_expr_l2<AB: AirBuilder<F = KoalaBear>>(bits: &[AB::Var]) -> AB::Expr {
    let mut acc: AB::Expr = KoalaBear::ZERO.into();
    for (i, bit) in bits.iter().enumerate() {
        let coeff = KoalaBear::from_u32(1u32 << i);
        acc = acc + (*bit).into() * coeff;
    }
    acc
}

fn eval_l2_shared_on_main_row<AB: AirBuilder<F = KoalaBear>>(
    b: &mut FilteredAirBuilder<'_, AB>,
    row: &[AB::Var],
) {
    let cur: &L2MainRow<AB::Var> = row.borrow();

    let qm1: AB::Expr = KoalaBear::from_u32(MODULUS as u32 - 1).into();

    for bit in cur.coeff_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    for bit in cur.delta_q_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    let ih: AB::Expr = cur.is_high.into();
    let one_h: AB::Expr = KoalaBear::ONE.into();
    b.assert_zero(ih.clone() * (ih.clone() - one_h));
    for bit in cur.slack_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    for bit in cur.accum_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }
    for bit in cur.bound_diff_bits.iter().copied() {
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        b.assert_zero(bit_e.clone() * (bit_e - one_b));
    }

    let e = bits_to_expr_l2::<AB>(&cur.coeff_bits);
    let delta_q = bits_to_expr_l2::<AB>(&cur.delta_q_bits);
    b.assert_zero(e.clone() + delta_q - qm1);

    let slack = bits_to_expr_l2::<AB>(&cur.slack_bits);
    let is_h: AB::Expr = cur.is_high.into();
    let one: AB::Expr = KoalaBear::ONE.into();
    let c6144: AB::Expr = KoalaBear::from_u32(MODULUS_MINUS_1_OVER_TWO as u32).into();
    let c6145: AB::Expr = KoalaBear::from_u32(MODULUS_MINUS_1_OVER_TWO as u32 + 1).into();
    let branch_lo = (one.clone() - is_h.clone()) * (e.clone() + slack.clone() - c6144);
    let branch_hi = is_h.clone() * (e.clone() - c6145 - slack);
    b.assert_zero(branch_lo + branch_hi);
}

/// Dual→L² boundary (transition row ending segment `s=0`): first L² contribution lands on `next`.
fn unified_l2_first_on_next_row<AB: AirBuilder<F = KoalaBear>>(
    b: &mut FilteredAirBuilder<'_, AB>,
) {
    let main_win = b.main();
    let next: &L2MainRow<AB::Var> = main_win.next_slice().borrow();
    let accum = bits_to_expr_l2::<AB>(&next.accum_bits);
    let contrib = falcon_l2_contrib::<AB>(next);
    b.assert_zero(accum - contrib);
    let diff = bits_to_expr_l2::<AB>(&next.bound_diff_bits);
    b.assert_zero(diff);
}

/// Strict L² interior transitions (`s=1` on both endpoints): recurrence + zero slack-diff rows.
fn unified_l2_mid_transition<AB: AirBuilder<F = KoalaBear>>(
    b: &mut FilteredAirBuilder<'_, AB>,
) {
    let main_win = b.main();
    let cur: &L2MainRow<AB::Var> = main_win.current_slice().borrow();
    let next: &L2MainRow<AB::Var> = main_win.next_slice().borrow();
    let cur_accum = bits_to_expr_l2::<AB>(&cur.accum_bits);
    let next_accum = bits_to_expr_l2::<AB>(&next.accum_bits);
    let next_contrib = falcon_l2_contrib::<AB>(next);
    b.assert_zero(next_accum - cur_accum - next_contrib);
    let cur_diff = bits_to_expr_l2::<AB>(&cur.bound_diff_bits);
    b.assert_zero(cur_diff);
}

/// L²→NTT boundary (last L² row): enforce bound witness against accumulated norm.
fn unified_l2_last_step_to_ntt<AB: AirBuilder<F = KoalaBear>>(
    b: &mut FilteredAirBuilder<'_, AB>,
) {
    let main_win = b.main();
    let cur: &L2MainRow<AB::Var> = main_win.current_slice().borrow();
    let accum = bits_to_expr_l2::<AB>(&cur.accum_bits);
    let diff = bits_to_expr_l2::<AB>(&cur.bound_diff_bits);
    let bound: AB::Expr = KoalaBear::from_u32(SIG_BOUND_U32).into();
    b.assert_zero(accum + diff - bound);
}

fn eval_ntt_full_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let prep_full = b.preprocessed().current_slice();
    let prep_ntt: &NttPrepRow<AB::Var> = prep_full[UNIFIED_NTT_PREP_OFF..][..NTT_PREP_COLS].borrow();
    let active = prep_ntt.active;
    let twiddle = prep_ntt.twiddle;
    let u_in = prep_ntt.u_in;
    let v_in = prep_ntt.v_in;

    let main_win = b.main();
    let m: &NttMainRow<AB::Var> = main_win.current_slice()[..NTT_MAIN_COLS].borrow();

    let one: AB::Expr = KoalaBear::ONE.into();
    let act: AB::Expr = active.into();
    b.assert_zero(act.clone() * (one.clone() - act.clone()));

    let not_act = one.clone() - act.clone();

    for bit in m
        .v_mul_bits
        .iter()
        .chain(m.quot_vs_bits.iter())
        .chain(m.out0_bits.iter())
        .chain(m.out1_bits.iter())
        .copied()
    {
        let z0 = not_act.clone() * bit.into();
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        let bool_e = bit_e.clone() * (bit_e - one_b);
        let z1 = act.clone() * bool_e;
        b.assert_zero(z0);
        b.assert_zero(z1);
    }
    b.assert_zero(not_act.clone() * m.q0.into());
    b.assert_zero(not_act.clone() * m.q1.into());
    let q0_e: AB::Expr = m.q0.into();
    let one_bit: AB::Expr = KoalaBear::ONE.into();
    let bool_q0 = q0_e.clone() * (q0_e.clone() - one_bit.clone());
    b.assert_zero(act.clone() * bool_q0);
    let q1_e: AB::Expr = m.q1.into();
    let bool_q1 = q1_e.clone() * (q1_e.clone() - one_bit);
    b.assert_zero(act.clone() * bool_q1);

    let u: AB::Expr = u_in.into();
    let v_in_e: AB::Expr = v_in.into();

    let mut v_mul: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        v_mul = v_mul + m.v_mul_bits[i].into() * coeff;
    }
    let mut quot_vs: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        quot_vs = quot_vs + m.quot_vs_bits[i].into() * coeff;
    }
    let mut out0: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        out0 = out0 + m.out0_bits[i].into() * coeff;
    }
    let mut out1: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        out1 = out1 + m.out1_bits[i].into() * coeff;
    }

    let q_embed: AB::Expr = KoalaBear::from_u32(u32::from(MODULUS)).into();
    let s: AB::Expr = twiddle.into();

    let prod_vs = v_in_e.clone() * s;
    b.assert_zero(act.clone() * (prod_vs - v_mul.clone() - quot_vs * q_embed.clone()));
    b.assert_zero(act.clone() * (u.clone() + v_mul.clone() - out0.clone() - m.q0.into() * q_embed.clone()));
    b.assert_zero(act * (u - v_mul + q_embed.clone() - out1 - m.q1.into() * q_embed));
}

impl<AB> Air<AB> for FalconUnifiedParsedVerifyAir
where
    AB: AirBuilder<F = KoalaBear>,
{
    fn eval(&self, builder: &mut AB) {
        #[cfg(not(feature = "unified-strip-segment-trans"))]
        {
            // Segment validity + dual/coeff + NTT transitions along genuine trace transitions only.
            let mut tr = builder.when_transition();
            let seg_cur: [AB::Var; UNIFIED_SEG_BITS] = {
                let p = tr.preprocessed().current_slice();
                [p[0], p[1], p[2]]
            };
            let seg_next: [AB::Var; UNIFIED_SEG_BITS] = {
                let p = tr.preprocessed().next_slice();
                [p[0], p[1], p[2]]
            };

            eval_segment_one_hot_three_vars(&mut tr, &seg_cur);
            eval_segment_one_hot_three_vars(&mut tr, &seg_next);

            #[cfg(not(feature = "unified-strip-stack-trans"))]
            {
                let s0_cur_e: AB::Expr = seg_cur[0].into();

                {
                    let mut d = tr.when(s0_cur_e.clone());
                    eval_dual_ntt_constraints(&mut d);
                }
                {
                    let mut d = tr.when(s0_cur_e.clone());
                    eval_coeff_constraints(&mut d);
                }

                let s2_cur_e: AB::Expr = seg_cur[2].into();
                {
                    let mut d = tr.when(s2_cur_e);
                    eval_ntt_full_constraints(&mut d);
                }
            }
        }

        // L² shared checks ([`eval_l2_shared_on_main_row`]): gate by segment `s1` so dual/NTT rows (same main
        // column layout) do not run coefficient slack/bit constraints meant for L² limbs.
        let s1_cur_cover: AB::Expr = builder.preprocessed().current_slice()[1].into();
        {
            let mut d = builder.when(s1_cur_cover.clone());
            let mw = d.main();
            let cur = mw.current_slice();
            eval_l2_shared_on_main_row(&mut d, cur);
        }

        {
            let mut tr = builder.when_transition();
            let pc = tr.preprocessed().current_slice();
            let pn = tr.preprocessed().next_slice();
            let s0_cur: AB::Expr = pc[0].into();
            let s1_cur: AB::Expr = pc[1].into();
            let s1_next: AB::Expr = pn[1].into();
            let s2_next: AB::Expr = pn[2].into();

            {
                let mut m = tr.when(s0_cur * s1_next.clone());
                unified_l2_first_on_next_row(&mut m);
            }
            {
                let mut m = tr.when(s1_cur.clone() * s1_next.clone());
                unified_l2_mid_transition(&mut m);
            }
            {
                let mut m = tr.when(s1_cur * s2_next);
                unified_l2_last_step_to_ntt(&mut m);
            }
        }

        #[cfg(not(feature = "unified-strip-lastrow-ntt"))]
        {
            let mut last = builder.when_last_row();
            let s2_last: AB::Expr = last.preprocessed().current_slice()[2].into();
            {
                let mut d = last.when(s2_last);
                eval_ntt_full_constraints(&mut d);
            }
        }
    }
}
