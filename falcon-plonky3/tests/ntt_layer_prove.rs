use falcon_plonky3::{
    build_ntt_layer_instance, butterfly_j_jht_s, stark_config_poseidon2, state_through_ntt_layer,
    FalconNttLayerAir, NTT_LAYER_MAIN_COLS,
};
use falcon_rust::{Polynomial, LOG_N, N};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_strict_usize;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn prove_each_ntt_layer() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let poly = Polynomial::rand(&mut rng);
    let w = NTT_LAYER_MAIN_COLS;

    let config = stark_config_poseidon2();

    for layer in 0..LOG_N {
        let expected = state_through_ntt_layer(&poly, layer);
        let (air, main_trace) = build_ntt_layer_instance(&poly, layer);
        FalconNttLayerAir::assert_valid_main_height(&main_trace);

        for row in 0..N / 2 {
            let (j, j2, _) = butterfly_j_jht_s(layer, row);
            let base = row * w;
            let o0_off = base + 4 * 14;
            let o1_off = base + 5 * 14;
            let mut out0 = 0u32;
            let mut out1 = 0u32;
            for i in 0..14 {
                out0 += main_trace.values[o0_off + i].as_canonical_u32() << i;
                out1 += main_trace.values[o1_off + i].as_canonical_u32() << i;
            }
            assert_eq!(out0 as u16, expected[j], "layer {layer} row {row} out0 @ {j}");
            assert_eq!(out1 as u16, expected[j2], "layer {layer} row {row} out1 @ {j2}");
        }

        let degree_bits = log2_strict_usize(main_trace.height());
        let (preprocessed_prover_data, preprocessed_vk) =
            setup_preprocessed(&config, &air, degree_bits).expect("preprocessed setup");

        let proof = prove_with_preprocessed(
            &config,
            &air,
            main_trace,
            &[],
            Some(&preprocessed_prover_data),
        );

        verify_with_preprocessed(&config, &air, &proof, &[], Some(&preprocessed_vk))
            .unwrap_or_else(|e| panic!("layer {layer} verify failed: {e:?}"));
    }
}
