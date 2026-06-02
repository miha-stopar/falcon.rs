//! Hash bundle witness coherence: one [`HashToPointResult`] feeds both Keccak and hash-to-point traces.

use falcon_plonky3::{
    air::hash_to_point::{COL_B0, COL_B1, COL_IS_REAL, NUM_HASH_MAIN_COLS},
    hash::{
        hash_to_point,
        witness::{build_hash_to_point_instance, build_hash_to_point_instance_from_result},
        SHAKE_SQUEEZE_LEN,
    },
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

#[test]
fn single_result_builds_same_hash_to_point_trace() {
    let msg = b"zk credential presentation";
    let nonce = [7u8; 40];
    let shake = hash_to_point(msg, &nonce);

    let (_, main_a, _) = build_hash_to_point_instance(msg, &nonce);
    let (_, main_b, _) = build_hash_to_point_instance_from_result(msg.len(), &shake);
    assert_eq!(main_a.values, main_b.values);
}

#[test]
fn trace_bytes_match_squeeze_stream() {
    let msg = b"coherence";
    let nonce = [3u8; 40];
    let shake = hash_to_point(msg, &nonce);
    let (_, main, _) = build_hash_to_point_instance_from_result(msg.len(), &shake);

    let mut ctr = 0usize;
    for row_idx in 0..main.height() {
        let row = &main.values[row_idx * NUM_HASH_MAIN_COLS..(row_idx + 1) * NUM_HASH_MAIN_COLS];
        if row[COL_IS_REAL] != KoalaBear::ONE {
            continue;
        }
        let b0 = row[COL_B0].as_canonical_u32();
        let b1 = row[COL_B1].as_canonical_u32();
        assert_eq!(shake.squeeze[ctr] as u32, b0);
        assert_eq!(shake.squeeze[ctr + 1] as u32, b1);
        ctr += 2;
        if ctr >= SHAKE_SQUEEZE_LEN {
            break;
        }
    }
}
