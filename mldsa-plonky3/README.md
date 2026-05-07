# mldsa-plonky3

Plonky3 (uni-stark) experiments for **ML-DSA-44** (FIPS 204, previously Dilithium2).

## Native crypto

- **Vendored implementation:** [`../third_party/ml-dsa`](../third_party/ml-dsa) (RustCrypto [signatures](https://github.com/RustCrypto/signatures) tree, Apache-2.0 / MIT).
- **Local patches** (for ZKP plumbing only):
  - `VerifyingKey::recomputed_challenge_bytes` — returns the hash challenge after the matrix/hint steps (same logic as verification).
  - `VerifyingKey::mu_for_verify_internal` — exposes `mu` matching `verify_internal`.
  - `Signature::c_tilde` — exposes the encoded challenge prefix.

## Current AIR (bootstrap)

[`MlDsa44ChallengeBytesAir`](src/air/ml_dsa44_challenge.rs): **32 rows**, **2 columns** per row:

| Col | Meaning |
|-----|---------|
| 0 | `c_tilde[i]` (byte `i` from signature) |
| 1 | recomputed challenge byte `i` |

Constraint: **equality** (KoalaBear embedding of bytes).

**Important:** Shake256, `sample_in_ball`, NTT / `A·z`, and `use_hint` still run **only in native Rust** via `ml-dsa`. The STARK does not yet prove those steps—only the final 32-byte check once honest witnesses are supplied.

## Roadmap

1. Commit `mu` / message binding (preprocessed or public values), analogous to Falcon `hm_ntt`.
2. Hash gadget: `Shake256` absorption for the challenge step (or hash outside + prove opening).
3. Polynomial / NTT layer for `A`, `z`, `t` arithmetic.
4. Hint / decomposition gadgets (`encode_w1`, `use_hint`).

## Run tests

```bash
RUSTFLAGS="-C target-cpu=native" cargo test -p mldsa-plonky3 --release
```
