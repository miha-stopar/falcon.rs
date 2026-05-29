//! AIR for the per-index dual-NTT verification equation (see `falcon-r1cs`
//! [`FalconDualNTTVerificationCircuit`](../../falcon-r1cs/src/circuits/falcon_dual_ntt.rs)).
//!
//! Enforces mod-`q` congruence via products in KoalaBear (safe below \(q^2\)) and
//! explicit division with 14-bit quotient witnesses.
//!
//! ## Public statement data (`pk_ntt`, `hm_ntt`)
//!
//! These are **not** in the committed preprocessed trace. They appear as **two periodic
//! columns** of period `N` (see [`BaseAir::periodic_columns`](p3_air::BaseAir::periodic_columns)):
//! both prover and verifier derive the same values from the [`FalconDualNttEquationAir`] struct,
//! and the STARK pipeline incorporates periodic parameters into the Fiat–Shamir transcript (see
//! Plonky3 `uni-stark` prover). That matches the README goal of binding the dual-NTT statement
//! to the intended public polynomials instead of hiding them only inside a prover-chosen trace.
//! Periodic **`hm_ntt`** is a **verifier-supplied** table (hash-to-point + NTT in Rust in this
//! crate); the AIR uses those values as given public data per row.
//!
//! ## Preprocessed NTT references
//!
//! Four **preprocessed** columns per row fix the verifier’s reference NTT values for
//! `sig_pos`, `sig_neg`, `v_pos`, `v_neg` at that index. The AIR requires the main trace’s
//! first four columns to match them, so a prover cannot satisfy the congruence with unrelated
//! NTT limbs while still passing verify under a verifier-rebuilt [`FalconDualNttEquationAir`].

use core::borrow::Borrow;

use p3_air::{
    Air, AirBuilder, BaseAir, FilteredAirBuilder, PeriodicAirBuilder, WindowAccess,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::{MODULUS, N};

/// Bits for quotient witnesses: max quotient is below \(q\) (see README).
pub const QUOT_BITS: usize = 14;

/// Dual-NTT AIR uses **periodic** columns for `pk_ntt` / `hm_ntt` (length `N` each), not a
/// committed preprocessed trace.
pub const NUM_DUAL_NTT_PERIODIC_COLUMNS: usize = 2;

/// Preprocessed: expected NTT samples for `sig_pos`, `sig_neg`, `v_pos`, `v_neg` (KoalaBear
/// embedding of residues mod `q`), height [`N`], one row per NTT index.
pub const NUM_DUAL_NTT_PREPROCESSED_COLS: usize = 4;

pub const NUM_MAIN_COLS: usize = 8 + 2 * QUOT_BITS;

#[repr(C)]
pub struct DualNttPreprocessedRow<F> {
    pub exp_sig_pos_ntt: F,
    pub exp_sig_neg_ntt: F,
    pub exp_v_pos_ntt: F,
    pub exp_v_neg_ntt: F,
}

impl<F> Borrow<DualNttPreprocessedRow<F>> for [F] {
    fn borrow(&self) -> &DualNttPreprocessedRow<F> {
        debug_assert_eq!(self.len(), NUM_DUAL_NTT_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<DualNttPreprocessedRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

#[repr(C)]
pub struct MainRow<F> {
    pub sig_pos_ntt: F,
    pub sig_neg_ntt: F,
    pub v_pos_ntt: F,
    pub v_neg_ntt: F,
    pub lhs_mod: F,
    pub rhs_mod: F,
    pub prod_sig_pos_pk: F,
    pub prod_sig_neg_pk: F,
    pub quot_l_bits: [F; QUOT_BITS],
    pub quot_r_bits: [F; QUOT_BITS],
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

/// `pk_ntt[i]`, `hm_ntt[i]` for `i ∈ [0,N)` as **public periodic parameters** (period `N`).
#[derive(Clone, Debug)]
pub struct FalconDualNttEquationAir {
    pk_ntt: Vec<KoalaBear>,
    hm_ntt: Vec<KoalaBear>,
    /// Reference NTT values (`sig_pos`, `sig_neg`, `v_pos`, `v_neg`) per row; verifier- and
    /// prover-built from the same `(pk, msg, sig)`.
    ntt_ref: RowMajorMatrix<KoalaBear>,
}

impl FalconDualNttEquationAir {
    /// `pk_ntt` and `hm_ntt` must each have length [`N`](falcon_rust::N); they are exposed as
    /// periodic columns for statement binding. `ntt_ref` must be `N ×`
    /// [`NUM_DUAL_NTT_PREPROCESSED_COLS`] (expected NTT limbs per index).
    pub fn new(
        pk_ntt: Vec<KoalaBear>,
        hm_ntt: Vec<KoalaBear>,
        ntt_ref: RowMajorMatrix<KoalaBear>,
    ) -> Self {
        assert_eq!(pk_ntt.len(), N, "pk_ntt length must be N");
        assert_eq!(hm_ntt.len(), N, "hm_ntt length must be N");
        assert_eq!(
            ntt_ref.height(),
            N,
            "ntt_ref height must be N (one row per NTT index)"
        );
        assert_eq!(
            ntt_ref.width(),
            NUM_DUAL_NTT_PREPROCESSED_COLS,
            "ntt_ref width must be NUM_DUAL_NTT_PREPROCESSED_COLS"
        );
        Self {
            pk_ntt,
            hm_ntt,
            ntt_ref,
        }
    }

    pub fn pk_ntt_values(&self) -> &[KoalaBear] {
        &self.pk_ntt
    }

    pub fn hm_ntt_values(&self) -> &[KoalaBear] {
        &self.hm_ntt
    }

    pub fn ntt_ref(&self) -> &RowMajorMatrix<KoalaBear> {
        &self.ntt_ref
    }
}

impl BaseAir<KoalaBear> for FalconDualNttEquationAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.ntt_ref.clone())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_DUAL_NTT_PREPROCESSED_COLS
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_DUAL_NTT_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Vec<Vec<KoalaBear>> {
        vec![self.pk_ntt.clone(), self.hm_ntt.clone()]
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn eval_row_constraints<AB>(b: &mut FilteredAirBuilder<'_, AB>)
where
    AB: AirBuilder<F = KoalaBear> + PeriodicAirBuilder<F = KoalaBear>,
{
    let per = b.periodic_values();
    assert_eq!(
        per.len(),
        NUM_DUAL_NTT_PERIODIC_COLUMNS,
        "expected pk_ntt and hm_ntt periodic columns"
    );
    let pk: AB::Expr = per[0].into();
    let hm: AB::Expr = per[1].into();

    let (exp_sp, exp_sn, exp_vp, exp_vn) = {
        let p: &DualNttPreprocessedRow<AB::Var> = b.preprocessed().current_slice().borrow();
        (
            p.exp_sig_pos_ntt,
            p.exp_sig_neg_ntt,
            p.exp_v_pos_ntt,
            p.exp_v_neg_ntt,
        )
    };

    let main_win = b.main();
    let m: &MainRow<AB::Var> = main_win.current_slice().borrow();

    let sig_p = m.sig_pos_ntt;
    let sig_n = m.sig_neg_ntt;
    let v_p = m.v_pos_ntt;
    let v_n = m.v_neg_ntt;

    b.assert_eq(sig_p, exp_sp);
    b.assert_eq(sig_n, exp_sn);
    b.assert_eq(v_p, exp_vp);
    b.assert_eq(v_n, exp_vn);
    let lhs = m.lhs_mod;
    let rhs = m.rhs_mod;
    let prod_sp = m.prod_sig_pos_pk;
    let prod_sn = m.prod_sig_neg_pk;

    for bit in m.quot_l_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.quot_r_bits.iter().copied() {
        b.assert_bool(bit);
    }

    b.assert_eq(prod_sp, sig_p * pk.clone());
    b.assert_eq(prod_sn, sig_n * pk);

    let sum_l = hm.clone() + v_n + prod_sn;
    let sum_r = v_p + prod_sp;

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

    b.assert_zero(sum_l - lhs - quot_l * q_embed);
    b.assert_zero(sum_r - rhs - quot_r * q_embed);
    b.assert_eq(lhs, rhs);
}

impl<AB> Air<AB> for FalconDualNttEquationAir
where
    AB: AirBuilder<F = KoalaBear> + PeriodicAirBuilder<F = KoalaBear>,
{
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_row_constraints(&mut t);

        let mut last = builder.when_last_row();
        eval_row_constraints(&mut last);
    }
}
