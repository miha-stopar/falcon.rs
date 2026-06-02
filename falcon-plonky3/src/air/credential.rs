//! AIR variants for **ZK credential** verification (fixed VK, private signature).
//!
//! These drop statement-specific **preprocessed reference** columns. Witness values live in the
//! main trace; public issuer data uses **periodic** columns (`pk_ntt`, `hm_ntt`) or **public_values**.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, PeriodicAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use falcon_rust::{MODULUS, N};

use super::coeff_dual_product_zero::{MainRow as CoeffMainRow, NUM_MAIN_COLS as COEFF_MAIN_COLS};
use super::dual_ntt_equation::{
    MainRow as DualMainRow, NUM_DUAL_NTT_PERIODIC_COLUMNS, NUM_MAIN_COLS as DUAL_MAIN_COLS,
    QUOT_BITS,
};
use super::l2_bound::{
    eval_common_credential, eval_first_accum_only, eval_last_bound_only, eval_mid_transition,
    NUM_MAIN_COLS as L2_MAIN_COLS,
};

/// Dual-NTT congruence with **public** periodic `pk_ntt` / `hm_ntt` only (no preprocessed NTT refs).
#[derive(Clone, Debug)]
pub struct FalconDualNttCredentialAir {
    pk_ntt: Vec<KoalaBear>,
    hm_ntt: Vec<KoalaBear>,
}

impl FalconDualNttCredentialAir {
    pub fn new(pk_ntt: Vec<KoalaBear>, hm_ntt: Vec<KoalaBear>) -> Self {
        assert_eq!(pk_ntt.len(), N);
        assert_eq!(hm_ntt.len(), N);
        Self { pk_ntt, hm_ntt }
    }
}

impl BaseAir<KoalaBear> for FalconDualNttCredentialAir {
    fn width(&self) -> usize {
        DUAL_MAIN_COLS
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_DUAL_NTT_PERIODIC_COLUMNS
    }

    fn periodic_columns(&self) -> Vec<Vec<KoalaBear>> {
        vec![self.pk_ntt.clone(), self.hm_ntt.clone()]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn eval_dual_row<AB>(b: &mut FilteredAirBuilder<'_, AB>)
where
    AB: AirBuilder<F = KoalaBear> + PeriodicAirBuilder<F = KoalaBear>,
{
    let per = b.periodic_values();
    let pk: AB::Expr = per[0].into();
    let hm: AB::Expr = per[1].into();

    let main_win = b.main();
    let m: &DualMainRow<AB::Var> = main_win.current_slice().borrow();
    let sig_p = m.sig_pos_ntt;
    let sig_n = m.sig_neg_ntt;
    let v_p = m.v_pos_ntt;
    let v_n = m.v_neg_ntt;
    let lhs = m.lhs_mod;
    let rhs = m.rhs_mod;
    let prod_sp = m.prod_sig_pos_pk;
    let prod_sn = m.prod_sig_neg_pk;

    for bit in m.quot_l_bits.iter().chain(m.quot_r_bits.iter()).copied() {
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

    b.assert_zero(sum_l - lhs - quot_l * q_embed.clone());
    b.assert_zero(sum_r - rhs - quot_r * q_embed);
    b.assert_eq(lhs, rhs);
}

impl<AB> Air<AB> for FalconDualNttCredentialAir
where
    AB: AirBuilder<F = KoalaBear> + PeriodicAirBuilder<F = KoalaBear>,
{
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_dual_row(&mut t);
        let mut last = builder.when_last_row();
        eval_dual_row(&mut last);
    }
}

/// Coefficient-domain `sig_pos[i]·sig_neg[i]=0` without preprocessed coefficient binding.
#[derive(Clone, Debug, Default)]
pub struct FalconCoeffDualCredentialAir;

impl BaseAir<KoalaBear> for FalconCoeffDualCredentialAir {
    fn width(&self) -> usize {
        COEFF_MAIN_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

fn eval_coeff_row<AB: AirBuilder<F = KoalaBear>>(b: &mut FilteredAirBuilder<'_, AB>) {
    let main_win = b.main();
    let m: &CoeffMainRow<AB::Var> = main_win.current_slice().borrow();
    for bit in m.sig_pos_bits.iter().chain(m.sig_neg_bits.iter()).copied() {
        b.assert_bool(bit);
    }
    let mut pos: AB::Expr = KoalaBear::ZERO.into();
    let mut neg: AB::Expr = KoalaBear::ZERO.into();
    for i in 0..QUOT_BITS {
        let coeff = KoalaBear::from_u32(1u32 << i);
        pos = pos + m.sig_pos_bits[i].into() * coeff;
        neg = neg + m.sig_neg_bits[i].into() * coeff;
    }
    b.assert_zero(pos * neg);
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconCoeffDualCredentialAir {
    fn eval(&self, builder: &mut AB) {
        let mut t = builder.when_transition();
        eval_coeff_row(&mut t);
        let mut last = builder.when_last_row();
        eval_coeff_row(&mut last);
    }
}

/// L² bound without preprocessed coefficient references (private coeffs in main trace only).
#[derive(Clone, Debug, Default)]
pub struct FalconL2CredentialAir;

impl BaseAir<KoalaBear> for FalconL2CredentialAir {
    fn width(&self) -> usize {
        L2_MAIN_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..L2_MAIN_COLS).collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        None
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconL2CredentialAir {
    fn eval(&self, builder: &mut AB) {
        eval_common_credential(builder);

        let mut first = builder.when_first_row();
        eval_first_accum_only(&mut first);

        let mut mid = builder.when_transition();
        eval_mid_transition(&mut mid);

        let mut last = builder.when_last_row();
        eval_last_bound_only(&mut last);
    }
}
