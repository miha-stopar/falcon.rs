//! Replay Fiat–Shamir like [`p3_uni_stark::verify_with_preprocessed`] through `zeta`, then print OOD
//! algebra (`folded_constraints · inv_vanishing` vs recomposed `quotient`). PCS is skipped.
#![allow(dead_code)]

use falcon_plonky3::{
    build_falcon_unified_parsed_verify_air,
    config::FalconStarkConfig,
    prove_falcon_parsed_verify_single_stark,
    stark_config_poseidon2,
};
use falcon_rust::KeyPair;
use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
use p3_air::{Air, BaseAir, RowWindow};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_uni_stark::{
    get_log_num_quotient_chunks, recompose_quotient_from_chunks, setup_preprocessed,
    validate_degree_bits, Proof, StarkGenericConfig, Val, VerifierConstraintFolder,
};
use p3_util::{checked_log_size_sum, log2_strict_usize};

#[test]
#[ignore = "manual: prints OOD algebra diagnostic"]
fn diagnose_unified_single_stark_ood_algebra() {
    let keypair = KeyPair::keygen();
    let msg = b"ood-diagnose unified single-STARK";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-ood-diagnose", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let proof: Proof<FalconStarkConfig> =
        prove_falcon_parsed_verify_single_stark(&keypair.public_key, msg.as_ref(), &sig);
    let config = stark_config_poseidon2();
    let air = build_falcon_unified_parsed_verify_air(&keypair.public_key, msg.as_ref(), &sig);

    let zk_ext = config.is_zk();
    let base_degree_bits = proof.degree_bits.checked_sub(zk_ext).expect("degree_bits >= zk");
    let (_, vk) = setup_preprocessed(&config, &air, base_degree_bits).expect("setup_preprocessed");

    let (_base_bits2, degree) =
        validate_degree_bits(None, proof.degree_bits, zk_ext).expect("validate_degree_bits");
    assert_eq!(
        degree,
        unified_trace_height(),
        "proof domain matches unified trace height"
    );

    let trace_domain = natural_kb_domain_for_degree(degree);
    let init_trace_domain = natural_kb_domain_for_degree(degree >> zk_ext);

    let opened = &proof.opened_values;
    assert_eq!(
        opened.trace_local.len(),
        air.width(),
        "trace_local width"
    );
    let pp_local = opened.preprocessed_local.as_ref().expect("preprocessed_local");
    let pp_next = opened.preprocessed_next.as_ref().expect("preprocessed_next");
    assert_eq!(pp_local.len(), vk.width);
    let expected_pp_next = if air.preprocessed_next_row_columns().is_empty() {
        0
    } else {
        vk.width
    };
    assert_eq!(pp_next.len(), expected_pp_next);

    let layout = AirLayout {
        preprocessed_width: vk.width,
        main_width: air.width(),
        num_public_values: air.num_public_values(),
        num_periodic_columns: air.num_periodic_columns(),
        ..Default::default()
    };
    let log_chunks =
        get_log_num_quotient_chunks::<Val<FalconStarkConfig>, _>(&air, layout, zk_ext);
    let (_, num_quotient_chunks) =
        checked_log_size_sum(log_chunks, zk_ext).expect("quotient chunk log sum");

    let (_, quotient_domain_size) =
        checked_log_size_sum(proof.degree_bits, log_chunks).expect("quotient domain log sum");
    let quotient_domain = trace_domain.create_disjoint_domain(quotient_domain_size);
    let quotient_chunks_domains = quotient_domain.split_domains(num_quotient_chunks);

    let sym_n =
        get_symbolic_constraints::<Val<FalconStarkConfig>, _>(&air, layout).len();
    eprintln!("symbolic base constraints count = {sym_n}");

    let mut challenger = config.initialise_challenger();
    challenger.observe(Val::<FalconStarkConfig>::from_usize(proof.degree_bits));
    challenger.observe(Val::<FalconStarkConfig>::from_usize(base_degree_bits));
    challenger.observe(Val::<FalconStarkConfig>::from_usize(vk.width));

    challenger.observe(proof.commitments.trace.clone());
    challenger.observe(vk.commitment.clone());
    let empty_pub: &[Val<FalconStarkConfig>] = &[];
    challenger.observe_slice(empty_pub);

    let alpha: FalconChallenge = challenger.sample_algebra_element();
    challenger.observe(proof.commitments.quotient_chunks.clone());
    if let Some(ref rc) = proof.commitments.random {
        challenger.observe(rc.clone());
    }
    let zeta: FalconChallenge = challenger.sample_algebra_element();

    let periodic_values: Vec<_> = air
        .periodic_columns()
        .iter()
        .map(|col| init_trace_domain.evaluate_periodic_column_at(col, zeta))
        .collect();

    let quotient = recompose_quotient_from_chunks::<FalconStarkConfig>(
        &quotient_chunks_domains,
        &opened.quotient_chunks,
        zeta,
    );

    let trace_next = opened
        .trace_next
        .as_ref()
        .expect("unified AIR uses next-row main columns");

    let sels = init_trace_domain.selectors_at_point(zeta);
    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(&opened.trace_local),
        RowMajorMatrixView::new_row(trace_next),
    );
    let preprocessed = VerticalPair::new(
        RowMajorMatrixView::new_row(pp_local),
        RowMajorMatrixView::new_row(pp_next),
    );
    let preprocessed_window =
        RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);

    let mut folder = VerifierConstraintFolder::<FalconStarkConfig> {
        main,
        preprocessed,
        preprocessed_window,
        periodic_values: &periodic_values,
        public_values: &[],
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha,
        accumulator: FalconChallenge::ZERO,
    };
    air.eval(&mut folder);
    let folded = folder.accumulator;
    let lhs = folded * sels.inv_vanishing;

    eprintln!("alpha = {alpha:?}");
    eprintln!("zeta = {zeta:?}");
    eprintln!("inv_vanishing (1/Z_H(zeta)) = {:?}", sels.inv_vanishing);
    eprintln!("folded constraints sum = {folded:?}");
    eprintln!("lhs = folded * inv_vanishing = {lhs:?}");
    eprintln!("quotient (recomposed) = {quotient:?}");
    eprintln!("lhs - quotient = {:?}", lhs - quotient);
}

type FalconChallenge = <FalconStarkConfig as StarkGenericConfig>::Challenge;

/// Same subgroup as KoalaBear [`p3_fri::two_adic_pcs::TwoAdicFriPcs::natural_domain_for_degree`] (shift = 1).
fn natural_kb_domain_for_degree(degree: usize) -> TwoAdicMultiplicativeCoset<KoalaBear> {
    TwoAdicMultiplicativeCoset::new(KoalaBear::ONE, log2_strict_usize(degree)).unwrap()
}

fn unified_trace_height() -> usize {
    falcon_plonky3::unified_trace_height()
}
