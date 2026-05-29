//! Regression probes for uni-stark OOD: quadratic transition constraints (`next` vs `cur^2`).
use falcon_plonky3::air::unified_parsed_verify::{UNIFIED_MAIN_WIDTH, UNIFIED_PREP_WIDTH};
use falcon_plonky3::stark_config_poseidon2;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, prove_with_preprocessed, setup_preprocessed, verify, verify_with_preprocessed};
use p3_util::log2_strict_usize;

#[derive(Clone, Debug)]
struct MinimalQuadNextAir;

impl BaseAir<KoalaBear> for MinimalQuadNextAir {
    fn width(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for MinimalQuadNextAir {
    fn eval(&self, builder: &mut AB) {
        let mut tr = builder.when_transition();
        let mw = tr.main();
        let cur: AB::Expr = mw.current_slice()[0].into();
        let next: AB::Expr = mw.next_slice()[0].into();
        tr.assert_zero(next - cur.clone() * cur);
    }
}

#[test]
fn uni_stark_proves_masked_next_squared_relation() {
    let config = stark_config_poseidon2();
    let air = MinimalQuadNextAir;

    let h = 8usize;
    let mut vals = Vec::with_capacity(h);
    let mut x = KoalaBear::from_u32(2);
    for _ in 0..h {
        vals.push(x);
        x = x * x;
    }
    let trace = RowMajorMatrix::new(vals, 1);
    let proof = prove(&config, &air, trace, &[]);
    verify(&config, &air, &proof, &[]).expect("minimal quadratic-next AIR should verify");
}

/// Same recurrence as [`MinimalQuadNextAir`], but with a committed width-1 preprocessed column (all ones).
#[derive(Clone)]
struct MinimalPrepQuadAir {
    prep: RowMajorMatrix<KoalaBear>,
}

impl BaseAir<KoalaBear> for MinimalPrepQuadAir {
    fn width(&self) -> usize {
        1
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.prep.clone())
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for MinimalPrepQuadAir {
    fn eval(&self, builder: &mut AB) {
        let mut tr = builder.when_transition();
        let pc = tr.preprocessed().current_slice()[0].into();
        let pn = tr.preprocessed().next_slice()[0].into();
        let mw = tr.main();
        let cur: AB::Expr = mw.current_slice()[0].into();
        let next: AB::Expr = mw.next_slice()[0].into();
        tr.assert_zero(pc * pn * (next - cur.clone() * cur));
    }
}

#[test]
fn uni_stark_proves_prep_masked_next_squared_relation() {
    let config = stark_config_poseidon2();

    let h = 8usize;
    let one = KoalaBear::from_u32(1);
    let prep = RowMajorMatrix::new(vec![one; h], 1);

    let air = MinimalPrepQuadAir { prep };

    let mut vals = Vec::with_capacity(h);
    let mut x = KoalaBear::from_u32(2);
    for _ in 0..h {
        vals.push(x);
        x = x * x;
    }
    let trace = RowMajorMatrix::new(vals, 1);

    let deg = log2_strict_usize(trace.height());
    let (pp, vk) = setup_preprocessed(&config, &air, deg).expect("prep setup");
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pp));
    verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk))
        .expect("minimal preprocessed quadratic-next AIR should verify");
}

/// Same masked quadratic on column 0, but main/preprocessed widths match the unified Falcon AIR layout.
#[derive(Clone)]
struct WideUnifiedDimsPrepQuadAir {
    prep: RowMajorMatrix<KoalaBear>,
}

impl BaseAir<KoalaBear> for WideUnifiedDimsPrepQuadAir {
    fn width(&self) -> usize {
        UNIFIED_MAIN_WIDTH
    }

    fn preprocessed_width(&self) -> usize {
        UNIFIED_PREP_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.prep.clone())
    }
}

impl<AB: AirBuilder<F = KoalaBear>> Air<AB> for WideUnifiedDimsPrepQuadAir {
    fn eval(&self, builder: &mut AB) {
        let mut tr = builder.when_transition();
        let pc = tr.preprocessed().current_slice()[0].into();
        let pn = tr.preprocessed().next_slice()[0].into();
        let mw = tr.main();
        let cur: AB::Expr = mw.current_slice()[0].into();
        let next: AB::Expr = mw.next_slice()[0].into();
        tr.assert_zero(pc * pn * (next - cur.clone() * cur));
    }
}

#[test]
fn uni_stark_wide_unified_dims_prep_masked_quad_verifies() {
    let config = stark_config_poseidon2();

    let h = 8usize;
    let zero = KoalaBear::from_u32(0);
    let one = KoalaBear::from_u32(1);

    let mut prep_vals = vec![zero; h * UNIFIED_PREP_WIDTH];
    for r in 0..h {
        prep_vals[r * UNIFIED_PREP_WIDTH] = one;
    }
    let prep = RowMajorMatrix::new(prep_vals, UNIFIED_PREP_WIDTH);

    let air = WideUnifiedDimsPrepQuadAir { prep };

    let mut x = KoalaBear::from_u32(2);
    let mut main_vals = vec![zero; h * UNIFIED_MAIN_WIDTH];
    for r in 0..h {
        main_vals[r * UNIFIED_MAIN_WIDTH] = x;
        x = x * x;
    }
    let trace = RowMajorMatrix::new(main_vals, UNIFIED_MAIN_WIDTH);

    let deg = log2_strict_usize(trace.height());
    let (pp, vk) = setup_preprocessed(&config, &air, deg).expect("wide prep setup");
    let proof = prove_with_preprocessed(&config, &air, trace, &[], Some(&pp));
    verify_with_preprocessed(&config, &air, &proof, &[], Some(&vk))
        .expect("wide-dims masked quadratic-next AIR should verify");
}
