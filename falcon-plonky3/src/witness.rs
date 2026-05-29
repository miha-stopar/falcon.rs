use falcon_rust::{
    DualNTTPolynomial, DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, LOG_N, N,
    MODULUS, MODULUS_MINUS_1_OVER_TWO, SIG_L2_BOUND,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::air::{
    build_ntt_full_main, build_ntt_full_preprocessed, butterfly_j_jht_s, state_before_ntt_layer,
    unified_parsed_verify::{
        FalconUnifiedParsedVerifyAir, UNIFIED_COEFF_MAIN_OFF, UNIFIED_COEFF_PREP_OFF,
        UNIFIED_DUAL_PREP_OFF, UNIFIED_MAIN_WIDTH, UNIFIED_NTT_PREP_OFF, UNIFIED_PKHM_EMB_OFF,
        UNIFIED_PREP_WIDTH, unified_body_rows, unified_trace_height,
    },
    ACCUM_BITS, BOUND_DIFF_BITS, COEFF_DUAL_ZERO_MAIN_COLS, COEFF_DUAL_ZERO_PREPROCESSED_COLS,
    DELTA_Q_BITS, FalconNttLayerAir, L2_MAIN_COLS, L2_PREPROCESSED_COLS, NTT_FULL_MAIN_COLS,
    NTT_FULL_PREPROCESSED_COLS, NUM_MAIN_COLS, NUM_DUAL_NTT_PREPROCESSED_COLS, NTT_LAYER_MAIN_COLS,
    QUOT_BITS, SLACK_BITS, ntt_full_trace_height,
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

fn koala_matrix_row(mat: &RowMajorMatrix<KoalaBear>, r: usize) -> &[KoalaBear] {
    let w = mat.width();
    let base = r * w;
    &mat.values[base..base + w]
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

fn assemble_unified_preprocessed_rows(
    height: usize,
    pk_ntt: &[KoalaBear],
    hm_ntt: &[KoalaBear],
    ntt_ref: &RowMajorMatrix<KoalaBear>,
    coeff_prep: &RowMajorMatrix<KoalaBear>,
    ntt_full_preps: [&RowMajorMatrix<KoalaBear>; 4],
) -> RowMajorMatrix<KoalaBear> {
    let wp = UNIFIED_PREP_WIDTH;
    let ntt_h = ntt_full_trace_height();
    debug_assert_eq!(pk_ntt.len(), N);
    debug_assert_eq!(hm_ntt.len(), N);
    debug_assert!(height >= unified_body_rows());
    debug_assert_eq!(ntt_ref.height(), N);
    debug_assert_eq!(ntt_ref.width(), NUM_DUAL_NTT_PREPROCESSED_COLS);
    debug_assert_eq!(coeff_prep.height(), N);
    debug_assert_eq!(coeff_prep.width(), COEFF_DUAL_ZERO_PREPROCESSED_COLS);

    let one = fe_u16(1);
    let zero = fe_u16(0);
    let zpad = fe_u16(0);
    let mut prep_vals = vec![zpad; height * wp];

    for r in 0..N {
        let base = r * wp;
        prep_vals[base] = one;
        prep_vals[base + 1] = zero;
        prep_vals[base + 2] = zero;
        let nr = koala_matrix_row(ntt_ref, r);
        for c in 0..NUM_DUAL_NTT_PREPROCESSED_COLS {
            prep_vals[base + UNIFIED_DUAL_PREP_OFF + c] = nr[c];
        }
        let cr = koala_matrix_row(coeff_prep, r);
        for c in 0..COEFF_DUAL_ZERO_PREPROCESSED_COLS {
            prep_vals[base + UNIFIED_COEFF_PREP_OFF + c] = cr[c];
        }
    }

    for r in 0..4 * N {
        let row = N + r;
        let base = row * wp;
        prep_vals[base] = zero;
        prep_vals[base + 1] = one;
        prep_vals[base + 2] = zero;
    }

    let ntt_start = N + 4 * N;
    for b in 0..4 {
        let prep_mat = ntt_full_preps[b];
        debug_assert_eq!(prep_mat.height(), ntt_h);
        debug_assert_eq!(prep_mat.width(), NTT_FULL_PREPROCESSED_COLS);
        let base_row = ntt_start + b * ntt_h;
        for i in 0..ntt_h {
            let row = base_row + i;
            let base = row * wp;
            prep_vals[base] = zero;
            prep_vals[base + 1] = zero;
            prep_vals[base + 2] = one;
            let pr = koala_matrix_row(prep_mat, i);
            for c in 0..NTT_FULL_PREPROCESSED_COLS {
                prep_vals[base + UNIFIED_NTT_PREP_OFF + c] = pr[c];
            }
        }
    }

    for row in unified_body_rows()..height {
        let base = row * wp;
        prep_vals[base] = zero;
        prep_vals[base + 1] = zero;
        prep_vals[base + 2] = one;
    }

    for row in 0..height {
        let ii = row % N;
        let b = row * wp + UNIFIED_PKHM_EMB_OFF;
        prep_vals[b] = pk_ntt[ii];
        prep_vals[b + 1] = hm_ntt[ii];
    }

    RowMajorMatrix::new(prep_vals, wp)
}

fn assemble_unified_main_rows(
    height: usize,
    dual_main: &RowMajorMatrix<KoalaBear>,
    coeff_main: &RowMajorMatrix<KoalaBear>,
    l2_main: &RowMajorMatrix<KoalaBear>,
    ntt_full_mains: [&RowMajorMatrix<KoalaBear>; 4],
) -> RowMajorMatrix<KoalaBear> {
    let wm = UNIFIED_MAIN_WIDTH;
    let ntt_h = ntt_full_trace_height();
    debug_assert_eq!(dual_main.height(), N);
    debug_assert_eq!(dual_main.width(), NUM_MAIN_COLS);
    debug_assert_eq!(coeff_main.height(), N);
    debug_assert_eq!(coeff_main.width(), COEFF_DUAL_ZERO_MAIN_COLS);
    debug_assert_eq!(l2_main.height(), 4 * N);
    debug_assert_eq!(l2_main.width(), L2_MAIN_COLS);

    let zpad = fe_u16(0);
    let mut main_vals = vec![zpad; height * wm];

    for r in 0..N {
        let base = r * wm;
        let dr = koala_matrix_row(dual_main, r);
        for c in 0..NUM_MAIN_COLS {
            main_vals[base + c] = dr[c];
        }
        let cr = koala_matrix_row(coeff_main, r);
        for c in 0..COEFF_DUAL_ZERO_MAIN_COLS {
            main_vals[base + UNIFIED_COEFF_MAIN_OFF + c] = cr[c];
        }
    }

    for r in 0..4 * N {
        let row = N + r;
        let base = row * wm;
        let lr = koala_matrix_row(l2_main, r);
        for c in 0..L2_MAIN_COLS {
            main_vals[base + c] = lr[c];
        }
    }

    let ntt_start = N + 4 * N;
    for b in 0..4 {
        let main_mat = ntt_full_mains[b];
        debug_assert_eq!(main_mat.height(), ntt_h);
        debug_assert_eq!(main_mat.width(), NTT_FULL_MAIN_COLS);
        let base_row = ntt_start + b * ntt_h;
        for i in 0..ntt_h {
            let row = base_row + i;
            let base = row * wm;
            let mr = koala_matrix_row(main_mat, i);
            for c in 0..NTT_FULL_MAIN_COLS {
                main_vals[base + c] = mr[c];
            }
        }
    }

    RowMajorMatrix::new(main_vals, wm)
}

/// Unified AIR only (stacked preprocessed trace including embedded `pk_ntt` / `hm_ntt`).
///
/// Verifier rebuilds this from `(pk, msg, sig)` the same way as the seven-proof bundle.
pub fn build_falcon_unified_parsed_verify_air(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> FalconUnifiedParsedVerifyAir {
    let (dual_air, _) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let coeff_prep = build_falcon_coeff_dual_product_zero_preprocessed(sig);

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let prep_sig_pos = build_ntt_full_preprocessed(&sig_poly.pos);
    let prep_sig_neg = build_ntt_full_preprocessed(&sig_poly.neg);
    let prep_v_pos = build_ntt_full_preprocessed(&v_dual.pos);
    let prep_v_neg = build_ntt_full_preprocessed(&v_dual.neg);

    let height = unified_trace_height();
    let preprocessed = assemble_unified_preprocessed_rows(
        height,
        dual_air.pk_ntt_values(),
        dual_air.hm_ntt_values(),
        dual_air.ntt_ref(),
        &coeff_prep,
        [&prep_sig_pos, &prep_sig_neg, &prep_v_pos, &prep_v_neg],
    );
    FalconUnifiedParsedVerifyAir::new(preprocessed)
}

/// [`FalconUnifiedParsedVerifyAir`] plus padded main trace (single-STARK parsed-verify witness).
pub fn build_falcon_unified_parsed_verify_instance(
    pk: &PublicKey,
    msg: &[u8],
    sig: &Signature,
) -> (FalconUnifiedParsedVerifyAir, RowMajorMatrix<KoalaBear>) {
    let (dual_air, dual_main) = build_falcon_dual_ntt_instance(pk, msg, sig);
    let (_, coeff_main) = build_falcon_coeff_dual_product_zero_instance(sig);
    let coeff_prep = build_falcon_coeff_dual_product_zero_preprocessed(sig);
    let l2_main = build_falcon_l2_bound_trace(pk, msg, sig);

    let sig_poly: DualPolynomial = sig.into();
    let pk_poly: Polynomial = pk.into();
    let hm = Polynomial::from_hash_of_message(msg, sig.nonce());
    let uh_pos = sig_poly.pos * pk_poly;
    let uh_neg = sig_poly.neg * pk_poly;
    let v = hm - uh_pos + uh_neg;
    let v_dual = DualPolynomial::from(&v);

    let prep_sig_pos = build_ntt_full_preprocessed(&sig_poly.pos);
    let prep_sig_neg = build_ntt_full_preprocessed(&sig_poly.neg);
    let prep_v_pos = build_ntt_full_preprocessed(&v_dual.pos);
    let prep_v_neg = build_ntt_full_preprocessed(&v_dual.neg);

    let main_sig_pos = build_ntt_full_main(&sig_poly.pos);
    let main_sig_neg = build_ntt_full_main(&sig_poly.neg);
    let main_v_pos = build_ntt_full_main(&v_dual.pos);
    let main_v_neg = build_ntt_full_main(&v_dual.neg);

    let height = unified_trace_height();
    let preprocessed = assemble_unified_preprocessed_rows(
        height,
        dual_air.pk_ntt_values(),
        dual_air.hm_ntt_values(),
        dual_air.ntt_ref(),
        &coeff_prep,
        [&prep_sig_pos, &prep_sig_neg, &prep_v_pos, &prep_v_neg],
    );
    let main = assemble_unified_main_rows(
        height,
        &dual_main,
        &coeff_main,
        &l2_main,
        [&main_sig_pos, &main_sig_neg, &main_v_pos, &main_v_neg],
    );
    let air = FalconUnifiedParsedVerifyAir::new(preprocessed);
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

/// Preprocessed trace for [`crate::air::FalconL2BoundAir`]: verifier-rebuilt expected coefficient
/// `e` per row (`4 * N` rows × 1 col), in row order `sig_pos`, `sig_neg`, `v_pos`, `v_neg`.
///
/// Binds the L² accumulation to the actual signature/`v` coefficients so the norm bound cannot be
/// satisfied with unrelated values. Rebuilt identically by prover and verifier from `(pk, msg, sig)`.
pub fn build_falcon_l2_bound_preprocessed(
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

    let total_rows = 4 * N;
    let mut vals = Vec::with_capacity(total_rows);
    for row in 0..total_rows {
        let (poly, idx) = match row / N {
            0 => (&sig_poly.pos, row % N),
            1 => (&sig_poly.neg, row % N),
            2 => (&v_dual.pos, row % N),
            3 => (&v_dual.neg, row % N),
            _ => unreachable!(),
        };
        vals.push(fe_u16(poly.coeff()[idx]));
    }
    RowMajorMatrix::new(vals, L2_PREPROCESSED_COLS)
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
