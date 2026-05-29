//! [`StatementBoundAir`]: a transparent AIR wrapper that declares a fixed number of public values
//! without altering the inner AIR's constraints.
//!
//! Plonky3's `uni-stark` driver observes the proof's `public_values` into the Fiat–Shamir
//! transcript (prover and verifier both call `challenger.observe_slice(public_values)`), and the
//! verifier rejects a proof whose `public_values.len()` differs from `air.num_public_values()`.
//!
//! Wrapping each sub-AIR of the Falcon bundle with this type and supplying the same
//! **statement digest** as `public_values` ties every sub-proof's transcript to one common
//! statement `(pk, msg, sig)`. The digest is *not* referenced by any constraint — binding comes
//! purely from the transcript — so the inner constraint system is unchanged.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

/// Wraps `inner` and reports `num_public_values`, forwarding every other [`BaseAir`]/[`Air`]
/// method unchanged.
#[derive(Clone, Debug)]
pub struct StatementBoundAir<A> {
    inner: A,
    num_public_values: usize,
}

impl<A> StatementBoundAir<A> {
    pub fn new(inner: A, num_public_values: usize) -> Self {
        Self {
            inner,
            num_public_values,
        }
    }

    pub fn inner(&self) -> &A {
        &self.inner
    }
}

impl<A: BaseAir<KoalaBear>> BaseAir<KoalaBear> for StatementBoundAir<A> {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        self.inner.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }

    fn num_periodic_columns(&self) -> usize {
        self.inner.num_periodic_columns()
    }

    fn periodic_columns(&self) -> Vec<Vec<KoalaBear>> {
        self.inner.periodic_columns()
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        self.inner.main_next_row_columns()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.inner.preprocessed_next_row_columns()
    }

    fn num_constraints(&self) -> Option<usize> {
        self.inner.num_constraints()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        self.num_public_values
    }
}

impl<AB, A> Air<AB> for StatementBoundAir<A>
where
    AB: AirBuilder<F = KoalaBear>,
    A: Air<AB>,
{
    fn eval(&self, builder: &mut AB) {
        self.inner.eval(builder);
    }
}
