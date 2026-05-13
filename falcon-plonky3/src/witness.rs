use falcon_rust::{
    DualNTTPolynomial, DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, LOG_N, N,
    MODULUS, MODULUS_MINUS_1_OVER_TWO, SIG_L2_BOUND,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{
    butterfly_j_jht_s, state_before_ntt_layer, ACCUM_BITS, BOUND_DIFF_BITS, COEFF_DUAL_ZERO_MAIN_COLS,
    COEFF_DUAL_ZERO_PREPROCESSED_COLS, DELTA_Q_BITS, FalconNttLayerAir, L2_MAIN_COLS, NUM_MAIN_COLS,
    NUM_DUAL_NTT_PREPROCESSED_COLS, NTT_LAYER_MAIN_COLS, QUOT_BITS, SLACK_BITS,
};
use crate::{FalconCoeffDualProductZeroAir, FalconDualNttEquationAir};

fn fe_u16(x: u16) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(u32::from(x))
}

fn fe_u32(x: u32) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(x)
}

fn u32_to_bits_le<const B: usize>(x: u32) -> [u16; B] {
    debug_assert!(B <= 32);
    let mut bits = [0u16; B];
    let mut v = x;
    for i in 0..B {
        bits[i] = (v & 1) as u16;
        v >>= 1;
    }
    debug_assert_eq!(v, 0, "value uses more than {B} bits");
    bits
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

/// Build preprocessed (`pk_ntt`, `hm_ntt`) and main traces from a valid Falcon tuple.
pub fn build_falcon_dual_ntt_instance(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> (FalconDualNttEquationAir, RowMajorMatrix<KoalaBear>) {
    let pk_poly: Polynomial = pk.into();
    let sig_poly: DualPolynomial = sig.into();

    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let hm_ntt = NTTPolynomial::from(&hm);

    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let pk_ntt = NTTPolynomial::from(&pk_poly);
    let sig_ntt = DualNTTPolynomial::from(&sig_poly);
    let v_ntt = DualNTTPolynomial::from(&v_dual);

    let mut pk_ntt_vals = Vec::with_capacity(N);
    let mut hm_ntt_vals = Vec::with_capacity(N);
    let mut ntt_ref_vals = Vec::with_capacity(N * NUM_DUAL_NTT_PREPROCESSED_COLS);
    let mut main_vals = Vec::with_capacity(N * NUM_MAIN_COLS);
    let q = u64::from(MODULUS);
    for i in 0..N {
        let pk_i = pk_ntt.coeff()[i];
        let sp = sig_ntt.pos.coeff()[i];
        let sn = sig_ntt.neg.coeff()[i];
        let vp = v_ntt.pos.coeff()[i];
        let vn = v_ntt.neg.coeff()[i];
        let hm_i = u64::from(hm_ntt.coeff()[i]);
        let pk_u = u64::from(pk_i);

        let prod_sp_u64 = u64::from(sp) * pk_u;
        let prod_sn_u64 = u64::from(sn) * pk_u;
        let sum_l = hm_i + u64::from(vn) + prod_sn_u64;
        let sum_r = u64::from(vp) + prod_sp_u64;
        let lhs = (sum_l % q) as u16;
        let rhs = (sum_r % q) as u16;
        debug_assert_eq!(lhs, rhs, "dual-NTT congruence failed at coefficient {i}");

        let quot_l = u16::try_from((sum_l - u64::from(lhs)) / q).expect("quot_l fits u16");
        let quot_r = u16::try_from((sum_r - u64::from(rhs)) / q).expect("quot_r fits u16");
        debug_assert!(quot_l < (1 << QUOT_BITS));
        debug_assert!(quot_r < (1 << QUOT_BITS));

        let bits_l = quot_to_bits_le(quot_l);
        let bits_r = quot_to_bits_le(quot_r);

        pk_ntt_vals.push(fe_u16(pk_i));
        hm_ntt_vals.push(fe_u16(hm_ntt.coeff()[i]));

        ntt_ref_vals.push(fe_u16(sp));
        ntt_ref_vals.push(fe_u16(sn));
        ntt_ref_vals.push(fe_u16(vp));
        ntt_ref_vals.push(fe_u16(vn));

        main_vals.push(fe_u16(sp));
        main_vals.push(fe_u16(sn));
        main_vals.push(fe_u16(vp));
        main_vals.push(fe_u16(vn));
        main_vals.push(fe_u16(lhs));
        main_vals.push(fe_u16(rhs));
        main_vals.push(fe_u32(prod_sp_u64 as u32));
        main_vals.push(fe_u32(prod_sn_u64 as u32));
        for b in bits_l {
            main_vals.push(fe_u16(b));
        }
        for b in bits_r {
            main_vals.push(fe_u16(b));
        }
    }
    debug_assert_eq!(main_vals.len(), N * NUM_MAIN_COLS);

    let main = RowMajorMatrix::new(main_vals, NUM_MAIN_COLS);
    let ntt_ref = RowMajorMatrix::new(ntt_ref_vals, NUM_DUAL_NTT_PREPROCESSED_COLS);
    let air = FalconDualNttEquationAir::new(pk_ntt_vals, hm_ntt_vals, ntt_ref);
    (air, main)
}

/// Main trace for [`crate::air::FalconL2BoundAir`]: `4 * N` rows
/// (`sig_pos`, `sig_neg`, `v_pos`, `v_neg` coefficients) and running L² accumulation.
pub fn build_falcon_l2_bound_trace(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> RowMajorMatrix<KoalaBear> {
    let pk_poly: Polynomial = pk.into();
    let sig_poly: DualPolynomial = sig.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let q = MODULUS as u32;
    let qm1 = q - 1;
    let half = MODULUS_MINUS_1_OVER_TWO as u32;
    let total_rows = 4 * N;
    let mut vals = Vec::with_capacity(total_rows * L2_MAIN_COLS);
    let mut accum_u64: u64 = 0;

    for row in 0..total_rows {
        let (poly, idx) = match row / N {
            0 => (&sig_poly.pos, row % N),
            1 => (&sig_poly.neg, row % N),
            2 => (&v_dual.pos, row % N),
            3 => (&v_dual.neg, row % N),
            _ => unreachable!(),
        };
        let e = u32::from(poly.coeff()[idx]);
        debug_assert!(e < q);
        let delta_q = qm1 - e;
        let is_high = if e > half { 1u32 } else { 0u32 };
        let slack_u32 = if is_high == 0 {
            half - e
        } else {
            e - (half + 1)
        };

        let m = if is_high == 0 { e } else { q - e };
        let contrib = (m as u64) * (m as u64);
        accum_u64 += contrib;

        for bit in quot_to_bits_le(e as u16) {
            vals.push(fe_u16(bit));
        }
        for bit in u32_to_bits_le::<DELTA_Q_BITS>(delta_q) {
            vals.push(fe_u16(bit));
        }
        vals.push(fe_u16(is_high as u16));
        for bit in u32_to_bits_le::<SLACK_BITS>(slack_u32) {
            vals.push(fe_u16(bit));
        }

        let accum_u32 = u32::try_from(accum_u64).expect("accum fits u32");
        for bit in u32_to_bits_le::<ACCUM_BITS>(accum_u32) {
            vals.push(fe_u16(bit));
        }

        let bound_diff = if row + 1 == total_rows {
            u32::try_from(SIG_L2_BOUND - accum_u64).expect("accum <= SIG_L2_BOUND")
        } else {
            0u32
        };
        for bit in u32_to_bits_le::<BOUND_DIFF_BITS>(bound_diff) {
            vals.push(fe_u16(bit));
        }
    }

    debug_assert_eq!(accum_u64, {
        let s = sig_poly.l2_norm();
        let v = v_dual.l2_norm();
        s + v
    });
    debug_assert!(accum_u64 <= SIG_L2_BOUND);

    RowMajorMatrix::new(vals, L2_MAIN_COLS)
}

/// Preprocessed trace for [`crate::air::FalconCoeffDualProductZeroAir`]: expected `sig_pos`,
/// `sig_neg` coefficients (KoalaBear-embedded) per row.
pub fn build_falcon_coeff_dual_product_zero_preprocessed(sig: &Signature) -> RowMajorMatrix<KoalaBear> {
    let sig_poly: DualPolynomial = sig.into();
    let mut vals = Vec::with_capacity(N * COEFF_DUAL_ZERO_PREPROCESSED_COLS);
    for i in 0..N {
        let pos = sig_poly.pos.coeff()[i];
        let neg = sig_poly.neg.coeff()[i];
        debug_assert!(u32::from(pos) < (1u32 << QUOT_BITS));
        debug_assert!(u32::from(neg) < (1u32 << QUOT_BITS));
        vals.push(fe_u16(pos));
        vals.push(fe_u16(neg));
    }
    RowMajorMatrix::new(vals, COEFF_DUAL_ZERO_PREPROCESSED_COLS)
}

/// Main trace for [`crate::air::FalconCoeffDualProductZeroAir`]: coefficient-domain `sig_pos`,
/// `sig_neg` as 14 + 14 little-endian bit columns per [`crate::air::QUOT_BITS`].
pub fn build_falcon_coeff_dual_product_zero_trace(sig: &Signature) -> RowMajorMatrix<KoalaBear> {
    let (_, main) = build_falcon_coeff_dual_product_zero_instance(sig);
    main
}

/// [`FalconCoeffDualProductZeroAir`] plus main trace, using verifier-rebuilt expected coefficients.
pub fn build_falcon_coeff_dual_product_zero_instance(
    sig: &Signature,
) -> (FalconCoeffDualProductZeroAir, RowMajorMatrix<KoalaBear>) {
    let prep = build_falcon_coeff_dual_product_zero_preprocessed(sig);
    let air = FalconCoeffDualProductZeroAir::new(prep);
    let sig_poly: DualPolynomial = sig.into();
    let w = COEFF_DUAL_ZERO_MAIN_COLS;
    let mut vals = Vec::with_capacity(N * w);
    for i in 0..N {
        let pos = u32::from(sig_poly.pos.coeff()[i]);
        let neg = u32::from(sig_poly.neg.coeff()[i]);
        debug_assert!(pos < (1u32 << QUOT_BITS));
        debug_assert!(neg < (1u32 << QUOT_BITS));
        for bit in quot_to_bits_le(pos as u16) {
            vals.push(fe_u16(bit));
        }
        for bit in quot_to_bits_le(neg as u16) {
            vals.push(fe_u16(bit));
        }
    }
    debug_assert_eq!(vals.len(), N * w);
    let main = RowMajorMatrix::new(vals, w);
    (air, main)
}

/// Main trace for [`crate::air::FalconNttLayerAir`]: one row per butterfly at NTT layer `layer`.
pub fn build_ntt_layer_main_trace(poly: &Polynomial, layer: usize) -> RowMajorMatrix<KoalaBear> {
    assert!(layer < LOG_N);
    let state = state_before_ntt_layer(poly, layer);
    let q = u32::from(MODULUS);
    let mut vals = Vec::with_capacity((N / 2) * NTT_LAYER_MAIN_COLS);
    for b in 0..N / 2 {
        let (j, j2, s) = butterfly_j_jht_s(layer, b);
        let u = u32::from(state[j]);
        let v_in = u32::from(state[j2]);
        let prod = v_in * u32::from(s);
        let v_mul = (prod % q) as u32;
        let quot_vs = u16::try_from((prod - v_mul) / q).expect("quot_vs fits");
        debug_assert!(u64::from(quot_vs) < (1u64 << QUOT_BITS));

        let out0 = (u + v_mul) % q;
        let out1 = (u + q - v_mul) % q;
        let q0: u16 = ((u + v_mul - out0) / q) as u16;
        let q1: u16 = ((u + q - v_mul - out1) / q) as u16;
        debug_assert!(q0 <= 1 && q1 <= 1);

        for bit in quot_to_bits_le(u as u16) {
            vals.push(fe_u16(bit));
        }
        for bit in quot_to_bits_le(v_in as u16) {
            vals.push(fe_u16(bit));
        }
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
    debug_assert_eq!(vals.len(), (N / 2) * NTT_LAYER_MAIN_COLS);
    RowMajorMatrix::new(vals, NTT_LAYER_MAIN_COLS)
}

/// Preprocessed + main traces for [`crate::air::FalconNttLayerAir`] at `layer`.
pub fn build_ntt_layer_instance(
    poly: &Polynomial,
    layer: usize,
) -> (FalconNttLayerAir, RowMajorMatrix<KoalaBear>) {
    assert!(layer < LOG_N);
    let prep = FalconNttLayerAir::preprocessed_for_layer(layer);
    let air = FalconNttLayerAir::new(prep);
    let main = build_ntt_layer_main_trace(poly, layer);
    (air, main)
}

/// Convenience: layer `0` main trace only (twiddles are uniform; use [`FalconNttLayerAir::new_for_layer0`]).
pub fn build_ntt_layer0_trace(poly: &Polynomial) -> RowMajorMatrix<KoalaBear> {
    build_ntt_layer_main_trace(poly, 0)
}
