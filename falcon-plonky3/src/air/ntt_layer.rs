//! One Cooley–Tukey **layer** of Falcon’s forward NTT (same indexing as [`falcon_rust::ntt`]).
//!
//! For layer `l ∈ [0, LOG_N)`: `m = 2^l`, stride `t = N / 2^l`, `ht = t/2`, butterfly pairs
//! `(j, j + ht)` with `s = NTT_TABLE[m + i]` where `i` and `j` come from the usual nested loops
//! (see [`butterfly_j_jht_s`]).
//!
//! Per butterfly (native reduction mod `q` each step):
//! - `v = (v_in * s) mod MODULUS`
//! - `out0 = (u + v) mod MODULUS`
//! - `out1 = (u + MODULUS - v) mod MODULUS`
//!
//! **Preprocessed trace:** one column, the twiddle `s` for that row (public / statement-dependent).
//!
//! **Composition** between layers (outputs of layer `l` feeding inputs of layer `l+1`) is not yet
//! enforced in a single proof; each layer is currently proved against native witness state.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use falcon_rust::{Polynomial, LOG_N, MODULUS, N, NTT_TABLE};

use super::dual_ntt_equation::QUOT_BITS;

pub const NUM_PREPROCESSED_COLS: usize = 1;

/// Six groups of `QUOT_BITS` little-endian bits (`u`, `v_in`, `v_mul`, `quot_vs`, `out0`, `out1`)
/// plus boolean `q0`, `q1` for the final reductions (`u + v_mul` and `u + MODULUS - v_mul` are
/// `< 2 * MODULUS`).
pub const NUM_MAIN_COLS: usize = 6 * QUOT_BITS + 2;

#[repr(C)]
pub struct PreprocessedRow<F> {
    pub twiddle: F,
}

#[repr(C)]
pub struct MainRow<F> {
    pub u_bits: [F; QUOT_BITS],
    pub v_bits: [F; QUOT_BITS],
    pub v_mul_bits: [F; QUOT_BITS],
    pub quot_vs_bits: [F; QUOT_BITS],
    pub out0_bits: [F; QUOT_BITS],
    pub out1_bits: [F; QUOT_BITS],
    pub q0: F,
    pub q1: F,
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

/// Row `b ∈ [0, N/2)` at layer `l`: left index `j`, right index `j + ht`, twiddle `s`.
pub fn butterfly_j_jht_s(layer: usize, butterfly_idx: usize) -> (usize, usize, u16) {
    assert!(layer < LOG_N);
    let m = 1usize << layer;
    let t = N >> layer;
    let ht = t / 2;
    assert!(butterfly_idx < m * ht);
    let i = butterfly_idx / ht;
    let j_local = butterfly_idx % ht;
    let j1 = i * t;
    let j = j1 + j_local;
    let s = NTT_TABLE[m + i];
    (j, j + ht, s)
}

/// Twiddle for layer 0, butterfly order (same as first row’s `s`); kept for docs/tests.
pub fn layer0_twiddle() -> u16 {
    butterfly_j_jht_s(0, 0).2
}

/// Apply one forward-NTT layer in-place (same nested loops as `falcon_rust`’s crate-private `ntt` in `arith`).
pub fn apply_ntt_layer(state: &mut [u16; N], layer: usize) {
    assert!(layer < LOG_N);
    let m = 1usize << layer;
    let t = N >> layer;
    let ht = t / 2;
    let mut i = 0usize;
    let mut j1 = 0usize;
    while i < m {
        let s = NTT_TABLE[m + i];
        let j2 = j1 + ht;
        let mut j = j1;
        while j < j2 {
            let u = state[j];
            let v = (state[j + ht] as u32 * s as u32 % MODULUS as u32) as u16;
            state[j] = (u + v) % MODULUS;
            state[j + ht] = (u + MODULUS - v) % MODULUS;
            j += 1;
        }
        i += 1;
        j1 += t;
    }
}

/// Coefficient state **before** applying layer `layer` (identity when `layer == 0`).
pub fn state_before_ntt_layer(poly: &Polynomial, layer: usize) -> [u16; N] {
    assert!(layer <= LOG_N);
    let mut s = *poly.coeff();
    for l in 0..layer {
        apply_ntt_layer(&mut s, l);
    }
    s
}

/// Apply layers `0..=layer` and return the array (full NTT when `layer == LOG_N - 1`).
pub fn state_through_ntt_layer(poly: &Polynomial, layer: usize) -> [u16; N] {
    assert!(layer < LOG_N);
    let mut s = state_before_ntt_layer(poly, layer);
    apply_ntt_layer(&mut s, layer);
    s
}

#[derive(Clone, Debug)]
pub struct FalconNttLayerAir {
    preprocessed: RowMajorMatrix<KoalaBear>,
}

impl FalconNttLayerAir {
    pub fn new(preprocessed: RowMajorMatrix<KoalaBear>) -> Self {
        assert_eq!(
            preprocessed.width(),
            NUM_PREPROCESSED_COLS,
            "preprocessed width = twiddle column"
        );
        assert_eq!(preprocessed.height(), N / 2);
        assert!(preprocessed.height().is_power_of_two());
        Self { preprocessed }
    }

    /// Layer `l = 0` only: constant twiddle column (same as [`layer0_twiddle`] on every row).
    pub fn new_for_layer0() -> Self {
        Self::new(Self::preprocessed_for_layer(0))
    }

    /// Twiddle column for layer `l` (deterministic; does not depend on polynomial values).
    pub fn preprocessed_for_layer(layer: usize) -> RowMajorMatrix<KoalaBear> {
        assert!(layer < LOG_N);
        let mut v = Vec::with_capacity((N / 2) * NUM_PREPROCESSED_COLS);
        for b in 0..N / 2 {
            let (_, _, s) = butterfly_j_jht_s(layer, b);
            v.push(KoalaBear::from_u32(u32::from(s)));
        }
        RowMajorMatrix::new(v, NUM_PREPROCESSED_COLS)
    }

    pub fn expected_height() -> usize {
        assert!(N.is_power_of_two());
        N / 2
    }

    pub fn assert_valid_main_height(main: &RowMajorMatrix<KoalaBear>) {
        assert_eq!(main.height(), Self::expected_height(), "NTT layer trace height N/2");
        assert!(main.height().is_power_of_two());
    }
}

impl BaseAir<KoalaBear> for FalconNttLayerAir {
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
        Some(3)
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

fn eval_row_constraints<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let prep_win = b.preprocessed();
    let prep: &PreprocessedRow<AB::Var> = prep_win.current_slice().borrow();
    let twiddle_fe = prep.twiddle;

    let main_win = b.main();
    let m: &MainRow<AB::Var> = main_win.current_slice().borrow();

    for bit in m.u_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.v_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.v_mul_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.quot_vs_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.out0_bits.iter().copied() {
        b.assert_bool(bit);
    }
    for bit in m.out1_bits.iter().copied() {
        b.assert_bool(bit);
    }
    b.assert_bool(m.q0);
    b.assert_bool(m.q1);

    let u = bits_to_expr::<AB>(&m.u_bits);
    let v_in = bits_to_expr::<AB>(&m.v_bits);
    let v_mul = bits_to_expr::<AB>(&m.v_mul_bits);
    let quot_vs = bits_to_expr::<AB>(&m.quot_vs_bits);
    let out0 = bits_to_expr::<AB>(&m.out0_bits);
    let out1 = bits_to_expr::<AB>(&m.out1_bits);

    let q_embed = KoalaBear::from_u32(u32::from(MODULUS));
    let s: AB::Expr = twiddle_fe.into();

    let prod_vs = v_in.clone() * s;
    b.assert_zero(prod_vs - v_mul.clone() - quot_vs * q_embed.clone());

    b.assert_zero(u.clone() + v_mul.clone() - out0.clone() - m.q0.into() * q_embed.clone());
    b.assert_zero(u - v_mul + q_embed - out1 - m.q1.into() * q_embed);
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconNttLayerAir {
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_row_constraints(&mut t);

        let mut last = builder.when_last_row();
        eval_row_constraints(&mut last);
    }
}

/// Backwards-compatible name for the generic layer AIR (layer 0 uses a constant twiddle column).
pub type FalconNttLayer0Air = FalconNttLayerAir;
