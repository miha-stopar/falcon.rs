mod coeff_dual_product_zero;
mod dual_ntt_equation;
mod l2_bound;
mod ntt_full;
mod ntt_layer;
pub mod unified_parsed_verify;

pub use coeff_dual_product_zero::{
    FalconCoeffDualProductZeroAir, NUM_MAIN_COLS as COEFF_DUAL_ZERO_MAIN_COLS,
    NUM_PREPROCESSED_COLS as COEFF_DUAL_ZERO_PREPROCESSED_COLS,
};
pub use dual_ntt_equation::{
    FalconDualNttEquationAir, NUM_DUAL_NTT_PERIODIC_COLUMNS, NUM_DUAL_NTT_PREPROCESSED_COLS,
    NUM_MAIN_COLS, QUOT_BITS,
};
pub use l2_bound::{
    FalconL2BoundAir, ACCUM_BITS, BOUND_DIFF_BITS, DELTA_Q_BITS, NUM_MAIN_COLS as L2_MAIN_COLS,
    NUM_PREPROCESSED_COLS as L2_PREPROCESSED_COLS, SLACK_BITS,
};
pub use ntt_full::{
    build_ntt_full_main, build_ntt_full_preprocessed, FalconNttFullAir,
    NUM_MAIN_COLS as NTT_FULL_MAIN_COLS,
    NUM_PREPROCESSED_COLS as NTT_FULL_PREPROCESSED_COLS,
    ntt_full_real_rows, ntt_full_trace_height,
};
pub use unified_parsed_verify::{
    FalconUnifiedParsedVerifyAir, unified_body_rows, unified_trace_height,
};
pub use ntt_layer::{
    apply_ntt_layer, butterfly_j_jht_s, layer0_twiddle, state_before_ntt_layer,
    state_through_ntt_layer, FalconNttLayer0Air, FalconNttLayerAir,
    NUM_MAIN_COLS as NTT_LAYER_MAIN_COLS,
    NUM_PREPROCESSED_COLS as NTT_LAYER_PREPROCESSED_COLS,
};
