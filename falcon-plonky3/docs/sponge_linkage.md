# Sponge ↔ hash-to-point linkage (Phase C remainder)

## Current pipeline

1. **Native squeeze** — [`shake256_context::hash_to_point_squeeze`](../../falcon-rust/src/shake.rs) produces `squeeze[]` and `hm` (Falcon C).
2. **Rust sponge simulator** — [`hash/shake.rs`](../src/hash/shake.rs) records `keccak_inputs` and `rate_after_perm` for `p3_keccak_air`.
3. **`shake_keccak` STARK** — proves Keccak-f on each `keccak_inputs[i]` preimage.
4. **`hash_to_point` STARK** — proves rejection sampling on `squeeze[]` (bytes in witness).

Credential prove uses one [`HashToPointResult`](../src/hash/shake.rs) for steps 2–4 ([`prove.rs`](../src/credential/prove.rs)).

## Gap

The Keccak sub-proof and the hash-to-point sub-proof are **not yet algebraically linked**:

- `shake_keccak` does not prove that its permutations are exactly those that produced the native `squeeze` bytes.
- `FalconHashToPointAir` does not read sponge rate columns (attempted `COL_RATE_*` linkage needs simulator ≡ C).

[`compute_squeeze_byte_refs`](../src/hash/shake.rs) maps native squeeze bytes into `rate_after_perm`; it currently returns `None` for real Falcon parameters (see ignored test `squeeze_provenance_matches_rate_snapshots`).

## Next steps

1. Align Rust [`ShakeState`](../src/hash/shake.rs) with Falcon C (or record rate from C in `falcon-rust`).
2. In-circuit: per sampling row, prove `b0,b1` equal rate bytes at `(block, offset)` into committed `rate_after_perm`.
3. Optionally merge sponge + sampling into one STARK or add a lookup argument between proofs.
