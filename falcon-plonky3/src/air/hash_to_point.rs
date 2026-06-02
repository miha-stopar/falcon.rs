//! In-circuit Falcon **hash-to-point** (rejection sampling from SHAKE squeeze bytes).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use falcon_rust::{LOG_N, MODULUS, N};

pub const HASH_MSG_MAX_BYTES: usize = 256;
pub const NUM_HASH_PUBLIC_VALUES: usize = N;

const THRESHOLD: u32 = 61445;
pub const SLACK_BITS: usize = 16;
/// `raw = coeff + quot * MODULUS` for accepted samples (`quot` ≤ 4).
pub const QUOT_BITS: usize = 3;

pub const COL_RAW: usize = 0;
pub const COL_B0: usize = 1;
pub const COL_B1: usize = 2;
pub const COL_ACCEPT: usize = 3;
pub const COL_COEFF: usize = 4;
/// Expected output coefficient (`hm[emit_ctr]`); witness copies native value on accept rows.
pub const COL_HM_REF: usize = 5;
pub const COL_EMIT_CTR: usize = 6;
pub const COL_SLACK_START: usize = 7;
pub const COL_QUOT_START: usize = COL_SLACK_START + SLACK_BITS;
pub const COL_EMIT_BITS_START: usize = COL_QUOT_START + QUOT_BITS;
pub const COL_IS_REAL: usize = COL_EMIT_BITS_START + LOG_N;

pub const NUM_HASH_MAIN_COLS: usize = COL_IS_REAL + 1;

#[derive(Clone, Debug)]
pub struct FalconHashToPointAir {
    msg_len: usize,
}

impl FalconHashToPointAir {
    pub fn new(msg_len: usize) -> Self {
        assert!(msg_len <= HASH_MSG_MAX_BYTES);
        Self { msg_len }
    }
}

impl BaseAir<KoalaBear> for FalconHashToPointAir {
    fn width(&self) -> usize {
        NUM_HASH_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_HASH_PUBLIC_VALUES
    }
}

fn bits_to_expr<AB: AirBuilder<F = KoalaBear>>(bits: &[AB::Var]) -> AB::Expr {
    let mut acc: AB::Expr = KoalaBear::ZERO.into();
    for (i, bit) in bits.iter().enumerate() {
        let coeff = KoalaBear::from_u32(1u32 << i);
        acc = acc + (*bit).into() * coeff;
    }
    acc
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for FalconHashToPointAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let w = main.current_slice();
        let is_real = w[COL_IS_REAL].clone();

        {
            let mut g = builder.when(is_real.clone());
            g.assert_zero(
                w[COL_B0].clone() * AB::Expr::from_u32(256) + w[COL_B1].clone() - w[COL_RAW].clone(),
            );
            g.assert_bool(w[COL_ACCEPT].clone());
            g.when(AB::Expr::ONE - w[COL_ACCEPT].clone())
                .assert_zero(w[COL_COEFF].clone());
        }

        let slack = bits_to_expr::<AB>(&w[COL_SLACK_START..COL_QUOT_START]);
        let quot = bits_to_expr::<AB>(&w[COL_QUOT_START..COL_EMIT_BITS_START]);
        {
            let mut g = builder.when(is_real.clone());
            g.when(w[COL_ACCEPT].clone()).assert_zero(
                w[COL_RAW].clone() + slack.clone() - AB::Expr::from_u32(THRESHOLD - 1),
            );
            for b in &w[COL_SLACK_START..COL_QUOT_START] {
                g.when(w[COL_ACCEPT].clone()).assert_bool(b.clone());
            }
            for b in &w[COL_QUOT_START..COL_EMIT_BITS_START] {
                g.when(w[COL_ACCEPT].clone()).assert_bool(b.clone());
            }
            g.when(w[COL_ACCEPT].clone()).assert_zero(
                w[COL_RAW].clone()
                    - w[COL_COEFF].clone()
                    - quot * AB::Expr::from_u32(u32::from(MODULUS)),
            );
        }

        let emit_bits = &w[COL_EMIT_BITS_START..COL_IS_REAL];
        {
            let mut g = builder.when(is_real.clone());
            for b in emit_bits {
                g.when(w[COL_ACCEPT].clone()).assert_bool(b.clone());
            }
            g.when(w[COL_ACCEPT].clone())
                .assert_eq(w[COL_COEFF].clone(), w[COL_HM_REF].clone());
            g.when(w[COL_ACCEPT].clone())
                .assert_eq(w[COL_EMIT_CTR].clone(), bits_to_expr::<AB>(emit_bits));
        }

        builder
            .when_last_row()
            .assert_eq(w[COL_EMIT_CTR].clone(), AB::Expr::from_u32(N as u32));

    }
}
