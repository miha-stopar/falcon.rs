# Unified single-STARK `OodEvaluationMismatch` — investigation log

Single-STARK parsed-verify (`prove_falcon_parsed_verify_single_stark` / `verify_falcon_parsed_verify_single_stark`) fails with `p3_uni_stark::VerificationError::OodEvaluationMismatch { index: None }` even though:

- `p3_air::check_constraints` accepts the full unified witness (`tests/unified_witness_constraints.rs`).
- The seven-proof bundle verifies (`verify_falcon_parsed_verify`).
- Standalone `FalconL2BoundAir` proves and verifies (`tests/l2_bound_prove.rs`).
- Minimal uni-stark probes with unified main/pre widths + quadratics pass (`tests/minimal_quad_next_air.rs`).

Uni-stark raises `OodEvaluationMismatch` when `verify_constraints` sees  
`folded_constraints * inv_vanishing != quotient` at the Fiat–Shamir point `ζ` (after PCS openings succeed).

## Trace geometry (Falcon-1024)

- `unified_body_rows = N + 4·N + 4·ntt_full_trace_height()` ≈ **37 888**.
- `unified_trace_height()` = `next_power_of_two(body)` = **65 536** → **~27.6k** padding rows.
- Padding preprocessed tail: segment `[0,0,1]` (NTT), remaining fixed columns mostly zero until cyclic `pk_ntt` / `hm_ntt` embed; main tail all zeros.

## What we ruled out

| Hypothesis | Result |
|------------|--------|
| Wrong `setup_preprocessed` / `proof.degree_bits` vs ZK (`verify` subtracts `config.is_zk()`) | Matches bundle pattern; `PreprocessedDegreeMismatch` does not fire. |
| `max_constraint_degree` too low / quotient chunks too small | Symbolic `degree_multiple` is **6** (unified) vs **5** (standalone L²); `log_quotient_chunks` is **3** vs **2**. Forcing `max_constraint_degree() -> Some(17)` (extra chunks) **still OOD**. |
| Padding filled with zeros vs duplicating last body row (full prep + main slice, then `pk`/`hm` overlay) | Duplication keeps `check_constraints` green; **still OOD**. Reverted to zero main / `[0,0,1]` segment padding to minimize witness churn. |
| Strip stacked sub-AIRs (Cargo features `unified-strip-stack-trans`, `unified-strip-segment-trans`, `unified-strip-lastrow-ntt`) | Even **L²-only** (segment transitions + dual/coeff/NTT blocks stripped, last-row NTT stripped) **still OOD**. Bug is not isolated to dual/coeff/butterfly transition blocks alone. |
| L² shared row gate `is_transition + is_last_row` vs `s1` only vs `when_transition · s1` | **All variants still OOD** (including restoring `when_transition().when(s1)` for shared L²). |

## Observations

1. **`check_constraints` uses cyclic next row** (`row_next = (row + 1) % height`). Uni-stark uses `ω`-shift at `ζ`. Transition-masked constraints are multiplied by `is_transition`, which vanishes on the last row, so the wrap usually does not falsify transition rows; constraints that only touch `current_slice()` are unaffected by wrap semantics.

2. **Transcript observation**: prover observes trace degrees as `from_u8(log_ext_degree)`, verifier as `from_usize(degree_bits)`. For `degree_bits ≤ 255` these embed the same field element; PCS verification succeeds up to the OOD check, so FS state is consistent through openings.

3. **OOD algebra diagnostic** (`tests/unified_ood_diagnose.rs`, ignored): replays the verifier Fiat–Shamir prefix exactly as `verify_with_preprocessed` (observe `degree_bits`, `base_degree_bits`, preprocessed width; trace + preprocessed commitments; empty public values; sample `α`; quotient commitments; sample `ζ`). PCS is skipped, but `quotient` is recomposed from chunk openings and `VerifierConstraintFolder` is evaluated on the proof openings at `ζ` with `init_trace_domain` selectors (same as `verify_constraints`). On Falcon-1024 this prints **`lhs - quotient ≠ 0`** while reporting **426** symbolic base constraints — confirming the failure is the folded constraint sum vs quotient at `ζ`, not an FS transcription mismatch.

## Recommendation

Until the OOD mismatch is understood upstream or locally instrumented, rely on **`prove_falcon_parsed_verify` / `verify_falcon_parsed_verify`** (seven proofs). Keep `prove_and_verify_unified_single_stark_parsed_verify` **ignored**. To reproduce the printed residual:  
`cargo test -p falcon-plonky3 diagnose_unified_single_stark_ood_algebra --release -- --ignored --nocapture`.

## Related files

- AIR: `src/air/unified_parsed_verify.rs`
- Witness: `src/witness.rs` (`assemble_unified_*`)
- Entrypoints: `src/full_verify.rs`
- Sanity: `tests/unified_witness_constraints.rs`, `tests/unified_single_stark_prove.rs`
- OOD algebra printout (ignored): `tests/unified_ood_diagnose.rs`
- Symbolic degree probe (ignored): `tests/unified_witness_constraints.rs` → `debug_print_unified_vs_l2_symbolic_degrees`
