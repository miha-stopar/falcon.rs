//! AIR for the per-index dual-NTT verification equation (see `falcon-r1cs`
//! `FalconDualNTTVerificationCircuit`).
//!
//! Enforces mod-`q` congruence via products in KoalaBear (safe below \(q^2\)) and
//! explicit division with 14-bit quotient witnesses.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::MODULUS;

/// Bits for quotient witnesses: max quotient is below \(q\) (see README).
pub const QUOT_BITS: usize = 14;

pub const NUM_PREPROCESSED_COLS: usize = 2;
pub const NUM_MAIN_COLS: usize = 8 + 2 * QUOT_BITS;

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
    pub lhs_mod: F,
    pub rhs_mod: F,
    pub prod_sig_pos_pk: F,
    pub prod_sig_neg_pk: F,
    pub quot_l_bits: [F; QUOT_BITS],
    pub quot_r_bits: [F; QUOT_BITS],
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
        // Boolean checks (degree 2) and products like quot·q, sig·pk (degree 2).
        Some(3)
    }
}

fn eval_row_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let prep_win = b.preprocessed();
    let prep: &PreprocessedRow<AB::Var> = prep_win.current_slice().borrow();
    let main_win = b.main();
    let m: &MainRow<AB::Var> = main_win.current_slice().borrow();

    let pk = prep.pk_ntt;
    let hm = prep.hm_ntt;
    let sig_p = m.sig_pos_ntt;
    let sig_n = m.sig_neg_ntt;
    let v_p = m.v_pos_ntt;
    let v_n = m.v_neg_ntt;
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

    // Integer products stay < q^2 < 2^31 < p_KoalaBear; field × matches ℤ.
    b.assert_eq(prod_sp, sig_p * pk);
    b.assert_eq(prod_sn, sig_n * pk);

    let sum_l = hm + v_n + prod_sn;
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

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconDualNttEquationAir {
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_row_constraints(&mut t);

        let mut last = builder.when_last_row();
        eval_row_constraints(&mut last);
    }
}
