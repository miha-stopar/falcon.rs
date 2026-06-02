//! STARK configuration (KoalaBear field, Poseidon2 Merkle / challenger).
//!
//! For a transparent, hash-centric PCS closer to a post-quantum footprint, swap the
//! Merkle layer to Keccak following `p3-uni-stark` tests and `p3-examples`.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
type Val = KoalaBear;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Default transparent STARK config used by tests and examples in this crate.
pub type FalconStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

type HidingValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    SmallRng,
    2,
    8,
    4,
>;
type HidingChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingValMmcs>;
type ZkPcs = HidingFriPcs<Val, Dft, HidingValMmcs, HidingChallengeMmcs, SmallRng>;

/// Zero-knowledge STARK config ([`HidingFriPcs`], witness-hiding Merkle commitments).
pub type FalconStarkZkConfig = StarkConfig<ZkPcs, Challenge, Challenger>;

/// Default STARK config using the standard KoalaBear width-16 Poseidon2 permutation.
pub fn stark_config_poseidon2() -> FalconStarkConfig {
    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    FalconStarkConfig::new(pcs, challenger)
}

/// ZK variant of [`stark_config_poseidon2`] (Phase B): same field and AIRs, hiding PCS.
pub fn stark_config_poseidon2_zk() -> FalconStarkZkConfig {
    let rng = SmallRng::seed_from_u64(1);
    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = HidingValMmcs::new(hash, compress, 0, rng);
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    // L² credential trace needs extra blowup under ZK (hiding adds a codeword slot).
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 2,
        max_log_arity: 1,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = ZkPcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        4,
        SmallRng::seed_from_u64(2),
    );
    let challenger = Challenger::new(perm);
    FalconStarkZkConfig::new(pcs, challenger)
}
