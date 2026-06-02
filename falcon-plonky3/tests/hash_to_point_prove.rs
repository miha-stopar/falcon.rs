use falcon_plonky3::{
    air::{FalconHashToPointAir, NUM_HASH_MAIN_COLS},
    hash::witness::build_hash_to_point_instance,
    stark_config_poseidon2,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_air::check_constraints;
use p3_uni_stark::{prove, verify};

use falcon_plonky3::air::hash_to_point::{COL_B0, COL_B1, COL_IS_REAL, COL_RAW};

#[test]
fn witness_row0_raw_identity() {
    let msg = b"zk credential presentation";
    let nonce = [7u8; 40];
    let (_, main, _) = build_hash_to_point_instance(msg, &nonce);
    let row = &main.values[0..NUM_HASH_MAIN_COLS];
    let lhs = row[COL_RAW];
    let rhs = row[COL_B0] * KoalaBear::from_u32(256) + row[COL_B1];
    assert_eq!(lhs, rhs);
    assert_eq!(row[COL_IS_REAL], KoalaBear::ONE);
}

#[test]
fn hash_to_point_prove_verify() {
    let msg = b"zk credential presentation";
    let nonce = [7u8; 40];
    let (air, main, pi) = build_hash_to_point_instance(msg, &nonce);
    check_constraints(&air, &main, &pi);
    let config = stark_config_poseidon2();
    let proof = prove(&config, &air, main, &pi);
    verify(&config, &air, &proof, &pi).expect("hash_to_point verify");
}

#[test]
fn hash_to_point_zk_prove_verify() {
    use falcon_plonky3::stark_config_poseidon2_zk;

    let msg = b"zk credential presentation";
    let nonce = [7u8; 40];
    let (air, main, pi) = build_hash_to_point_instance(msg, &nonce);
    check_constraints(&air, &main, &pi);
    let config = stark_config_poseidon2_zk();
    let proof = prove(&config, &air, main, &pi);
    verify(&config, &air, &proof, &pi).expect("hash_to_point zk verify");
}
