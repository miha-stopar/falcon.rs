//! Witness for [`super::shake::hash_to_point`] + [`crate::air::FalconHashToPointAir`].

use falcon_rust::{N, MODULUS};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use falcon_rust::LOG_N;

use crate::air::hash_to_point::{
    FalconHashToPointAir, COL_ACCEPT, COL_B0, COL_B1, COL_COEFF, COL_EMIT_BITS_START,
    COL_EMIT_CTR, COL_HM_REF, COL_IS_REAL, COL_QUOT_START, COL_RAW, COL_SLACK_START,
    HASH_MSG_MAX_BYTES,
    NUM_HASH_MAIN_COLS, NUM_HASH_PUBLIC_VALUES, QUOT_BITS, SLACK_BITS,
};
use crate::hash::shake::HashToPointResult;
use crate::hash::shake::hash_to_point;

fn fe_u32(x: u32) -> KoalaBear {
    <KoalaBear as PrimeCharacteristicRing>::from_u32(x)
}

fn fe_u16(x: u16) -> KoalaBear {
    fe_u32(u32::from(x))
}

fn u32_to_bits_le<const B: usize>(x: u32) -> [u16; B] {
    let mut bits = [0u16; B];
    let mut v = x;
    for i in 0..B {
        bits[i] = (v & 1) as u16;
        v >>= 1;
    }
    bits
}

/// Build hash-to-point AIR, main trace, and public values (`hm` coefficients).
pub fn build_hash_to_point_instance(
    msg: &[u8],
    nonce: &[u8],
) -> (
    FalconHashToPointAir,
    RowMajorMatrix<KoalaBear>,
    Vec<KoalaBear>,
) {
    assert!(msg.len() <= HASH_MSG_MAX_BYTES);
    assert_eq!(nonce.len(), 40);
    build_hash_to_point_instance_from_result(msg.len(), &hash_to_point(msg, nonce))
}

/// Same as [`build_hash_to_point_instance`] but reuses an existing [`HashToPointResult`]
/// (shared with [`super::prove_keccak::prove_shake_keccak`] on the same sponge run).
pub fn build_hash_to_point_instance_from_result(
    msg_len: usize,
    result: &HashToPointResult,
) -> (
    FalconHashToPointAir,
    RowMajorMatrix<KoalaBear>,
    Vec<KoalaBear>,
) {
    assert!(msg_len <= HASH_MSG_MAX_BYTES);
    let air = FalconHashToPointAir::new(msg_len);
    let main = build_hash_to_point_main(result);
    let public_values: Vec<KoalaBear> = result
        .hm
        .coeff()
        .iter()
        .map(|&c| fe_u16(c))
        .collect();
    debug_assert_eq!(public_values.len(), NUM_HASH_PUBLIC_VALUES);
    (air, main, public_values)
}

fn build_hash_to_point_main(result: &HashToPointResult) -> RowMajorMatrix<KoalaBear> {
    let mut rows: Vec<Vec<KoalaBear>> = Vec::new();
    let mut ctr = 0usize;
    let mut emit_ctr = 0u32;
    while emit_ctr < N as u32 {
        let b0 = result.squeeze[ctr];
        let b1 = result.squeeze[ctr + 1];
        ctr += 2;
        let raw = u32::from(b0) << 8 | u32::from(b1);
        debug_assert_eq!(raw, u32::from(b0) * 256 + u32::from(b1));
        let accept = raw < 61445;
        let coeff = if accept {
            (raw % MODULUS as u32) as u16
        } else {
            0
        };
        let quot = if accept { raw / MODULUS as u32 } else { 0 };
        let slack = if accept {
            61444u32.saturating_sub(raw)
        } else {
            0
        };
        let emit_bits = u32_to_bits_le::<LOG_N>(emit_ctr);

        let mut row = vec![KoalaBear::ZERO; NUM_HASH_MAIN_COLS];
        row[COL_B0] = fe_u32(u32::from(b0));
        row[COL_B1] = fe_u32(u32::from(b1));
        row[COL_RAW] = row[COL_B0] * fe_u32(256) + row[COL_B1];
        row[COL_ACCEPT] = fe_u32(u32::from(accept as u8));
        row[COL_COEFF] = fe_u16(coeff);
        row[COL_HM_REF] = fe_u16(if accept { result.hm.coeff()[emit_ctr as usize] } else { 0 });
        row[COL_EMIT_CTR] = fe_u32(emit_ctr);
        for (i, bit) in u32_to_bits_le::<{ SLACK_BITS }>(slack).iter().enumerate() {
            row[COL_SLACK_START + i] = fe_u32(u32::from(*bit));
        }
        for (i, bit) in u32_to_bits_le::<{ QUOT_BITS }>(quot).iter().enumerate() {
            row[COL_QUOT_START + i] = fe_u32(u32::from(*bit));
        }
        for (i, bit) in emit_bits.iter().enumerate() {
            row[COL_EMIT_BITS_START + i] = fe_u32(u32::from(*bit));
        }
        row[COL_IS_REAL] = fe_u32(1);
        rows.push(row);
        if accept {
            emit_ctr += 1;
        }
    }

    let height = rows.len().next_power_of_two().max(8);
    let mut pad_row = vec![KoalaBear::ZERO; NUM_HASH_MAIN_COLS];
    pad_row[COL_EMIT_CTR] = fe_u32(N as u32);
    pad_row[COL_IS_REAL] = fe_u32(0);
    rows.resize(height, pad_row);
    let values: Vec<KoalaBear> = rows.into_iter().flatten().collect();
    RowMajorMatrix::new(values, NUM_HASH_MAIN_COLS)
}

pub fn hash_to_point_trace_height() -> usize {
    // Upper bound padding; actual height comes from witness builder.
    (SHAKE_SQUEEZE_LEN / 2).next_power_of_two().max(8)
}

use crate::hash::SHAKE_SQUEEZE_LEN;
