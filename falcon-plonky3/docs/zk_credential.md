# ZK credential verification (OpenAC / Vega style)

Target use case: prove in zero-knowledge that the prover holds a valid credential signed by a known issuer—e.g. OpenAC ([ePrint 2026/251](https://eprint.iacr.org/2026/251.pdf)) and Vega ([ePrint 2025/2094](https://eprint.iacr.org/2025/2094.pdf))—without revealing the signature or credential bytes beyond what the policy requires.

## What those systems require

| Property | Vega / OpenAC-style | Previous `full_verify` path |
|----------|---------------------|----------------------------|
| **Fixed verification key** | One proving/verifier key per circuit shape (credential length bound, predicate family) | Per-`(pk, msg, sig)` preprocessed PCS commitments |
| **Public inputs** | Issuer key, policy / message digest, presentation context | Verifier rebuilds entire AIR from secret `sig` |
| **Private witness** | Credential bytes, signature, parsing hints | `sig` used to build “reference” preprocessed columns |
| **ZK** | Hiding commitments + ZK PCS / folding | Transparent STARK, no witness hiding today |
| **Hash + verify in-circuit** | SHA-256 + ECDSA (Vega); issuer signature on attributes | `hm` / hash-to-point **outside** the AIR |

## Redesign principles (this crate)

### 1. Preprocessed = **circuit-fixed only**

Plonky3 “preprocessed” columns are committed in `PreprocessedVerifierKey` and must be **identical for every proof** of the same circuit (Falcon-1024, etc.).

**Belongs in preprocessed (reusable VK):**

- NTT butterfly **twiddles** from `NTT_TABLE` (depend only on layer index)
- **Active-row selectors** for padded trace geometry (`active ∈ {0,1}`)

**Does not belong in preprocessed (was statement-specific):**

- `sig_pos` / `sig_neg` / `v_*` NTT samples or coefficients
- Expected coeff refs for dual-zero / L²
- Per-polynomial NTT inputs `u_in`, `v_in`

Those move to the **main witness** (private in ZK) or to **public inputs** (issuer `pk`, message binding).

### 2. Public vs private split (Falcon parsed-verify)

| Data | Role in credential proof |
|------|---------------------------|
| Issuer `pk` | **Public** — periodic `pk_ntt` derived from `pk` |
| Message / policy bytes | **Public** — defines what is being attested |
| `sig` (coeffs, dual limbs) | **Private** — main trace + sub-proofs |
| `hm = H(msg, nonce)` | **Public** as `hm` coeffs today; nonce stays in witness until Phase C is wired |
| Predicate (age, etc.) | **Public** constraints on opened attributes (future) |

### 3. Fixed keys module

[`credential`](../src/credential/mod.rs) exposes:

- `FalconCredentialVerifyKeys` — one-time `setup_preprocessed` for universal NTT twiddles
- `FalconCredentialPublicInputs` — issuer `pk`, `msg`, and public `hm` coefficients
- `prove_credential` / `verify_credential` — signature in witness only; fixed NTT VK

The legacy [`full_verify`](../src/full_verify.rs) path remains for transparent verification with verifier-rebuilt references.

### 4. Roadmap

| Phase | Deliverable |
|-------|-------------|
| **A (done)** | Universal NTT preprocessed; credential keys + API; credential AIRs without statement preprocessed binding |
| **B** | ZK-enabled PCS (`HidingFriPcs`); witness hiding |
| **C (in progress)** | In-circuit SHAKE256 + hash-to-point (`FalconHashToPointAir`, `p3_keccak_air`) |
| **D** | Single credential AIR or recursive aggregation (fixed outer VK) |
| **E** | Policy predicates (range on attributes via lookups, Vega-style) |

## Phase B — zero-knowledge (what it means here)

Phase **B** is **not** “the second step of the credential API.” It means: move from a **transparent** STARK to a **zero-knowledge** proof.

### Transparent today

- The prover commits to the full witness trace (signature coefficients, NTT limbs, etc.).
- The proof is sound, but a verifier who sees the proof data learns the committed witness at the queried points (and in practice the scheme is not designed to hide the signature).

### Phase B goal

Use Plonky3’s **ZK PCS** mode:

- `HidingFriPcs` instead of `TwoAdicFriPcs`
- `StarkConfig::is_zk() == 1` (extra blinded column / adjusted degree)
- Merkle commitments that **hide** trace values (see `uni-stark/tests/fib_air.rs` `make_zk_config()`)

The **algebraic constraints** (dual-NTT, L², NTT, etc.) stay the same; only the **polynomial commitment layer** changes so the proof is zero-knowledge.

### What Phase B does *not* do

| Topic | Phase |
|-------|--------|
| Fixed VK / universal preprocessed | **A** |
| Hide signature in witness | **B** (hiding PCS) |
| Prove `hm = H(msg, nonce)` in-circuit | **C** |
| One proof / one outer VK | **D** |

### Sketch for this repo

Add `stark_config_poseidon2_zk()` (KoalaBear + `HidingFriPcs` + Keccak MMCS, mirroring Plonky3 tests) and optionally `prove_credential_zk` using that config. Prover cost increases; verifier gets ZK.

## Phase C — hash in circuit (in progress)

Falcon hash-to-point: `SHAKE256(nonce, msg)` → squeeze → rejection sampling → `hm`.

| Piece | Status |
|-------|--------|
| Native squeeze helper | `falcon_rust::shake256_context::hash_to_point_squeeze` |
| `FalconHashToPointAir` | Rejection sampling + `hm` coeffs via witness `COL_HM_REF` (prove/verify test passes) |
| `p3_keccak_air` sponge steps | Witness recorded; wiring + Falcon `process_block` match WIP |
| Credential bundle | `hash_to_point` sub-proof bound to credential digest (rejection sampling; `hm` via digest + downstream AIRs) |

Until Phase C is wired, the prover sets `public.hm` from native `Polynomial::from_hash_of_message` (same as today’s verifiers).

## API sketch

```rust
let keys = FalconCredentialVerifyKeys::setup(&config)?;

let public = FalconCredentialPublicInputs::from_presentation(&issuer_pk, msg, &sig);
// `public.hm` is the message-hash polynomial (native for now; in-circuit in Phase C).

let proof = prove_credential(&config, &keys, &public, &sig)?;
verify_credential(&config, &keys, &public, &proof)?;
```

## Comparison to seven-proof `full_verify`

The old bundle is sound for **transparent** verification with verifier-rebuilt references. It is **not** suitable as-is for ZK credentials because:

1. Preprocessed commitments changed per signature → no reusable VK.
2. Verifier needed `sig` to rebuild references → no ZK for the signature.
3. Seven independent transcripts (mitigated by `statement_digest`, not one fixed VK).

The credential path fixes (1) and (2) for NTT and binding; **B** adds witness hiding; **C** adds in-circuit `hm`.
