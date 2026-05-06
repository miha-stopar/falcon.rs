use falcon_rust::{
    DualNTTPolynomial, DualPolynomial, NTTPolynomial, Polynomial, PublicKey, Signature, N,
    MODULUS,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{NUM_MAIN_COLS, NUM_PREPROCESSED_COLS};
use crate::FalconDualNttEquationAir;

fn fe(x: u16) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(u32::from(x))
}

/// Build preprocessed (`pk_ntt`, `hm_ntt`) and main (`sig`, `v` dual NTT limbs) traces from a
/// valid Falcon tuple. Callers should ensure `pk.verify(msg, sig)` succeeds.
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
        let lhs = (hm_i + u64::from(vn) + u64::from(sn) * pk_u) % q;
        let rhs = (u64::from(vp) + u64::from(sp) * pk_u) % q;
        debug_assert_eq!(lhs, rhs, "dual-NTT congruence failed at coefficient {i}");

        prep_vals.push(fe(pk_i));
        prep_vals.push(fe(hm_ntt.coeff()[i]));
        main_vals.push(fe(sp));
        main_vals.push(fe(sn));
        main_vals.push(fe(vp));
        main_vals.push(fe(vn));
        main_vals.push(fe(lhs as u16));
        main_vals.push(fe(rhs as u16));
    }

    let preprocessed = RowMajorMatrix::new(prep_vals, NUM_PREPROCESSED_COLS);
    let main = RowMajorMatrix::new(main_vals, NUM_MAIN_COLS);
    let air = FalconDualNttEquationAir::new(preprocessed);
    (air, main)
}
