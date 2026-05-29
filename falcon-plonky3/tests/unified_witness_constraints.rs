use falcon_plonky3::{
    build_falcon_l2_bound_preprocessed, build_falcon_unified_parsed_verify_air,
    build_falcon_unified_parsed_verify_instance, FalconL2BoundAir,
};
use falcon_rust::KeyPair;
use p3_air::check_constraints;
use p3_air::symbolic::{AirLayout, get_max_constraint_degree_extension};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::get_log_num_quotient_chunks;

type Challenge = BinomialExtensionField<KoalaBear, 4>;

/// Sanity-check the unified witness against the AIR in the base field (not extension / quotient).
#[test]
fn unified_witness_satisfies_air_check_constraints() {
    let keypair = KeyPair::keygen();
    let msg = b"check_constraints unified";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-check-unified", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));
    let (air, main) = build_falcon_unified_parsed_verify_instance(&keypair.public_key, msg, &sig);
    check_constraints(&air, &main, &[]);
}

/// Inspect uni-stark’s symbolic constraint-degree heuristic vs standalone L² (debug aid).
#[test]
#[ignore = "manual: prints symbolic degrees"]
fn debug_print_unified_vs_l2_symbolic_degrees() {
    let keypair = KeyPair::keygen();
    let msg = b"degree probe";
    let sig = keypair
        .secret_key
        .sign_with_seed(b"seed-deg", msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    let unified_air = build_falcon_unified_parsed_verify_air(&keypair.public_key, msg.as_ref(), &sig);
    let unified_layout = AirLayout::from_air(&unified_air);
    let u_deg =
        get_max_constraint_degree_extension::<KoalaBear, Challenge, _>(&unified_air, unified_layout);
    let u_chunks = get_log_num_quotient_chunks::<KoalaBear, _>(&unified_air, unified_layout, 0);

    let l2_prep = build_falcon_l2_bound_preprocessed(&keypair.public_key, msg.as_ref(), &sig);
    let l2_air = FalconL2BoundAir::new(l2_prep);
    let l2_layout = AirLayout::from_air(&l2_air);
    let l2_deg = get_max_constraint_degree_extension::<KoalaBear, Challenge, _>(&l2_air, l2_layout);
    let l2_chunks = get_log_num_quotient_chunks::<KoalaBear, _>(&l2_air, l2_layout, 0);

    eprintln!("standalone L2: symbolic_deg={l2_deg} log_quotient_chunks={l2_chunks}");
    eprintln!("unified:       symbolic_deg={u_deg} log_quotient_chunks={u_chunks}");
}
