//! All **`LOG_N`** Cooley–Tukey layers of Falcon’s forward NTT in **one** padded trace.
//!
//! Preprocessed columns fix **`(u, v)`** inputs per butterfly (from the statement polynomial in
//! clear text — same model as public `pk_ntt` / `hm_ntt` in the dual-NTT AIR). The prover shows
//! correct modular butterfly arithmetic for every real row; padding rows (`active = 0`) force
//! **main = 0**.
//!
//! One proof replaces **`LOG_N`** separate [`super::ntt_layer::FalconNttLayerAir`] proofs per
//! polynomial limb.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::{Polynomial, LOG_N, MODULUS, N};

use super::dual_ntt_equation::QUOT_BITS;
use super::ntt_layer::{butterfly_j_jht_s, state_before_ntt_layer};

pub const NUM_PREPROCESSED_COLS: usize = 4;
/// `v_mul`, `quot_vs`, `out0`, `out1` bit groups + `q0`, `q1`.
pub const NUM_MAIN_COLS: usize = 4 * QUOT_BITS + 2;

/// `real_butterflies = (N/2) * LOG_N`; trace height is the next power of two (padding).
pub fn ntt_full_real_rows() -> usize {
    (N / 2) * LOG_N
}

pub fn ntt_full_trace_height() -> usize {
    ntt_full_real_rows().next_power_of_two()
}

#[repr(C)]
pub struct PreprocessedFullRow<F> {
    pub active: F,
    pub twiddle: F,
    pub u_in: F,
    pub v_in: F,
}

#[repr(C)]
pub struct MainFullRow<F> {
    pub v_mul_bits: [F; QUOT_BITS],
    pub quot_vs_bits: [F; QUOT_BITS],
    pub out0_bits: [F; QUOT_BITS],
    pub out1_bits: [F; QUOT_BITS],
    pub q0: F,
    pub q1: F,
}

impl<F> Borrow<PreprocessedFullRow<F>> for [F] {
    fn borrow(&self) -> &PreprocessedFullRow<F> {
        debug_assert_eq!(self.len(), NUM_PREPROCESSED_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PreprocessedFullRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<F> Borrow<MainFullRow<F>> for [F] {
    fn borrow(&self) -> &MainFullRow<F> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainFullRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

#[derive(Clone, Debug)]
pub struct FalconNttFullAir {
    preprocessed: RowMajorMatrix<KoalaBear>,
}

impl FalconNttFullAir {
    pub fn new(preprocessed: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(preprocessed.width(), NUM_PREPROCESSED_COLS);
        assert_eq!(preprocessed.height(), ntt_full_trace_height());
        Self { preprocessed }
    }
}

impl BaseAir<KoalaBear> for FalconNttFullAir {
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
        Some(4)
    }
}

fn bits_to_expr<AB: AirBuilder<F = KoalaBear>>(bits: &[AB::Var; QUOT_BITS]) -> AB::Expr {
    let mut acc: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        acc = acc + bits[i].into() * coeff;
    }
    acc
}

fn eval_row<AB: AirBuilder<F = KoalaBear>>(builder: &mut AB) {
    let (active, twiddle, u_in, v_in) = {
        let prep_win = builder.preprocessed();
        let prep: &PreprocessedFullRow<AB::Var> = prep_win.current_slice().borrow();
        (prep.active, prep.twiddle, prep.u_in, prep.v_in)
    };
    let (v_mul_bits, quot_vs_bits, out0_bits, out1_bits, q0, q1) = {
        let main_win = builder.main();
        let m: &MainFullRow<AB::Var> = main_win.current_slice().borrow();
        (
            m.v_mul_bits,
            m.quot_vs_bits,
            m.out0_bits,
            m.out1_bits,
            m.q0,
            m.q1,
        )
    };

    builder.assert_bool(active);
    let one: AB::Expr = KoalaBear::ONE.into();
    let act: AB::Expr = active.into();
    let not_act = one - act.clone();

    for bit in v_mul_bits
        .iter()
        .chain(quot_vs_bits.iter())
        .chain(out0_bits.iter())
        .chain(out1_bits.iter())
        .copied()
    {
        let z0: AB::Expr = not_act.clone() * bit.into();
        let bit_e: AB::Expr = bit.into();
        let one_b: AB::Expr = KoalaBear::ONE.into();
        let bool_e = bit_e.clone() * (bit_e - one_b);
        let z1: AB::Expr = act.clone() * bool_e;
        builder.assert_zero(z0);
        builder.assert_zero(z1);
    }
    builder.assert_zero(not_act.clone() * q0.into());
    builder.assert_zero(not_act.clone() * q1.into());
    let q0_e: AB::Expr = q0.into();
    let one_q: AB::Expr = KoalaBear::ONE.into();
    let bool_q0 = q0_e.clone() * (q0_e - one_q);
    builder.assert_zero(act.clone() * bool_q0);
    let q1_e: AB::Expr = q1.into();
    let one_q1: AB::Expr = KoalaBear::ONE.into();
    let bool_q1 = q1_e.clone() * (q1_e - one_q1);
    builder.assert_zero(act.clone() * bool_q1);

    let u: AB::Expr = u_in.into();
    let v_in_e: AB::Expr = v_in.into();
    let v_mul = bits_to_expr::<AB>(&v_mul_bits);
    let quot_vs = bits_to_expr::<AB>(&quot_vs_bits);
    let out0 = bits_to_expr::<AB>(&out0_bits);
    let out1 = bits_to_expr::<AB>(&out1_bits);

    let q_embed = KoalaBear::from_u32(u32::from(MODULUS));
    let s: AB::Expr = twiddle.into();

    let prod_vs = v_in_e.clone() * s;
    builder.assert_zero(act.clone() * (prod_vs - v_mul.clone() - quot_vs * q_embed.clone()));
    builder.assert_zero(
        act.clone() * (u.clone() + v_mul.clone() - out0.clone() - q0.into() * q_embed.clone()),
    );
    builder.assert_zero(act * (u - v_mul + q_embed - out1 - q1.into() * q_embed));
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconNttFullAir {
    fn eval(&self, builder: &mut AB) {
        eval_row(builder);
    }
}

fn fe_u16(x: u16) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(u32::from(x))
}

fn quot_to_bits_le(x: u16) -> [u16; QUOT_BITS] {
    debug_assert!(x < (1u16 << QUOT_BITS as u16));
    let mut bits = [0u16; QUOT_BITS];
    let mut v = u32::from(x);
    for i in 0..QUOT_BITS {
        bits[i] = (v & 1) as u16;
        v >>= 1;
    }
    bits
}

/// Build preprocessed trace: `active`, twiddle, inputs `u`,`v` for each butterfly; padding rows inactive.
pub fn build_ntt_full_preprocessed(poly: &Polynomial) -> RowMajorMatrix<KoalaBear> {
    let h = ntt_full_trace_height();
    let real = ntt_full_real_rows();
    let mut vals = Vec::with_capacity(h * NUM_PREPROCESSED_COLS);
    for r in 0..h {
        if r < real {
            let layer = r / (N / 2);
            let b = r % (N / 2);
            let st = state_before_ntt_layer(poly, layer);
            let (j, j2, s) = butterfly_j_jht_s(layer, b);
            vals.push(KoalaBear::ONE);
            vals.push(fe_u16(s));
            vals.push(fe_u16(st[j]));
            vals.push(fe_u16(st[j2]));
        } else {
            vals.push(KoalaBear::ZERO);
            vals.push(KoalaBear::ZERO);
            vals.push(KoalaBear::ZERO);
            vals.push(KoalaBear::ZERO);
        }
    }
    RowMajorMatrix::new(vals, NUM_PREPROCESSED_COLS)
}

/// Main trace for [`FalconNttFullAir`].
pub fn build_ntt_full_main(poly: &Polynomial) -> RowMajorMatrix<KoalaBear> {
    let h = ntt_full_trace_height();
    let real = ntt_full_real_rows();
    let q = u32::from(MODULUS);
    let mut vals = Vec::with_capacity(h * NUM_MAIN_COLS);
    for r in 0..h {
        if r >= real {
            for _ in 0..NUM_MAIN_COLS {
                vals.push(KoalaBear::ZERO);
            }
            continue;
        }
        let layer = r / (N / 2);
        let b = r % (N / 2);
        let st = state_before_ntt_layer(poly, layer);
        let (j, j2, s) = butterfly_j_jht_s(layer, b);
        let u = u32::from(st[j]);
        let v_in = u32::from(st[j2]);
        let prod = v_in * u32::from(s);
        let v_mul = (prod % q) as u32;
        let quot_vs = u16::try_from((prod - v_mul) / q).expect("quot_vs");
        let out0 = (u + v_mul) % q;
        let out1 = (u + q - v_mul) % q;
        let q0: u16 = ((u + v_mul - out0) / q) as u16;
        let q1: u16 = ((u + q - v_mul - out1) / q) as u16;
        debug_assert!(q0 <= 1 && q1 <= 1);

        for bit in quot_to_bits_le(v_mul as u16) {
            vals.push(fe_u16(bit));
        }
        for bit in quot_to_bits_le(quot_vs) {
            vals.push(fe_u16(bit));
        }
        for bit in quot_to_bits_le(out0 as u16) {
            vals.push(fe_u16(bit));
        }
        for bit in quot_to_bits_le(out1 as u16) {
            vals.push(fe_u16(bit));
        }
        vals.push(fe_u16(q0));
        vals.push(fe_u16(q1));
    }
    debug_assert_eq!(vals.len(), h * NUM_MAIN_COLS);
    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}
