use falcon_rust::{
    DualNTTPolynomial, DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, N,
    MODULUS,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{NUM_MAIN_COLS, NUM_PREPROCESSED_COLS, QUOT_BITS};
use crate::FalconDualNttEquationAir;

fn fe_u16(x: u16) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(u32::from(x))
}

fn fe_u32(x: u32) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(x)
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

    let mut prep_vals = Vec::with_capacity(N * NUM_PREPROCESSED_COLS);
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

        prep_vals.push(fe_u16(pk_i));
        prep_vals.push(fe_u16(hm_ntt.coeff()[i]));

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

    let preprocessed = RowMajorMatrix::new(prep_vals, NUM_PREPROCESSED_COLS);
    let main = RowMajorMatrix::new(main_vals, NUM_MAIN_COLS);
    let air = FalconDualNttEquationAir::new(preprocessed);
    (air, main)
}
