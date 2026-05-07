# Post-quantum signatures × post-quantum-friendly SNARKs: experiment plan

> **Purpose.** Living document for comparing **NIST-standardized post-quantum (PQ) signature schemes** when used inside or alongside **PQ-friendly proof systems** (transparent / hash-first SNARKs, lattice-oriented arguments, etc.). Intended for HackMD: copy sections, fill tables, attach benchmark logs.

**Related notes & tooling**

- Community write-up (context on PQ signatures and proof systems): [hackmd.io/@0xvikasrushi/ryyMLdxCZl](https://hackmd.io/@0xvikasrushi/ryyMLdxCZl)
- **JARDIN** (Ethereum notes + repo): [notes.ethereum.org/@niard/JARDIN](https://notes.ethereum.org/@niard/JARDIN), [github.com/nconsigny/JARDIN](https://github.com/nconsigny/JARDIN)

---

## 1. Scope & methodology

### 1.1 What we compare

| Layer | Question |
|-------|----------|
| **Signature primitive** | Verification cost in-circuit (R1CS / AIR / custom arithmetization) |
| **Proof system** | Prover time, verifier time, proof size, setup model (transparent vs trusted), PQ assumptions |
| **Composition** | How public inputs (e.g. hashed message, key commitments) enter the statement |

### 1.2 Suggested benchmark metrics (placeholders)

Fill per `(scheme, proof system, security level)` row:

| Metric | Unit | Notes |
|--------|------|--------|
| R1CS constraints | # | Arkworks / gnark / circom-style |
| AIR trace length | rows × width | Plonky3 / STARK-style |
| Prover wall time | s | Same hardware class, note CPU model |
| Prover RAM | GB | Peak RSS |
| Verifier wall time | ms / µs | On-chain vs server |
| Proof size | KB | Include hashes / PCS layer |
| Setup | — | Transparent vs universal SRS vs ceremony |

**Hardware / software footer (template)**

```text
CPU:
RAM:
OS:
Rust / toolchain:
Commit / version:
Features (e.g. falcon-512 vs falcon-1024):
```

---

## 2. Standardized schemes (summary table)

| Signature | NIST / status | Type | Approx R1CS constraints | Sig size | PK size | Stateful |
|-----------|---------------|------|-------------------------|----------|---------|----------|
| **XMSS** | [SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) | Hash-based | *TBD* | *TBD* | *TBD* | **Yes** |
| **SLH-DSA-128s** (SPHINCS+) | [FIPS 205](https://csrc.nist.gov/publications/detail/fips/205/final) | Hash-based | *TBD* | *TBD* | *TBD* | **No** |
| **FN-DSA-512** (Falcon) | [FIPS 206](https://csrc.nist.gov/publications/detail/fips/206/final) | Lattice (NTRU) | *TBD* | *TBD* | *TBD* | **No** |
| **ML-DSA-44** (Dilithium) | [FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final) | Lattice (module) | *TBD* | *TBD* | *TBD* | **No** |

*Replace “Approx R1CS constraints” with AIR cost or a short note if the primary backend is STARK-only.*

---

## 3. Hash-based signatures

### 3.1 XMSS (SP 800-208)

**Summary.** Merkle–tree + one-time signatures; **stateful** (signer must track index / not reuse OTS keys).

**ZK / SNARK pain points**

- **Statefulness:** Proving “I signed with a fresh index” couples the proof to wallet / indexer state; batching and aggregation are awkward.
- **Large verification:** Many hash calls and tree paths → **high constraint count** or **long traces** unless optimized (e.g. dedicated hash gadgets, lookups).
- **Parameter zoo:** XMSSMT vs XMSS, SHA2 vs SHAKE, height / tree shape change cost profiles.

**Experiment checklist (placeholders)**

- [ ] Baseline: count hashes + Merkle path depth for one verify at chosen parameter set.
- [ ] R1CS / AIR size for SHA-256 vs SHAKE (match NIST profile).
- [ ] Compare transparent PCS (FRI / WHIR) vs hash-only Merkle in outer proof.
- [ ] Document state oracle: how the circuit receives `index` and OTS public key (public input vs committed).

**Results**

| Experiment | Result | Link / artifact |
|------------|--------|------------------|
| *TBD* | | |

---

### 3.2 SLH-DSA (SPHINCS+) — e.g. SLH-DSA-128s (FIPS 205)

**Summary.** Stateless hash-based signatures; verification is **many** hash permutations and tree / forest walks (parameter-set dependent).

**ZK / SNARK pain points**

- **Very high verification cost** in constraints for “small” parameter sets; proof time dominates many applications unless the statement is batched or outsourced.
- **Serialization / encoding:** Parsing and domain separation must match FIPS byte layout bit-for-bit in-circuit.
- **Memory / proving:** Long traces → RAM and FFT-dominated provers.

**Experiment checklist (placeholders)**

- [ ] Fix parameter set (e.g. 128s vs 128f) and implementation (reference vs optimized).
- [ ] Profile: # of hash calls per verify; map to R1CS rows or AIR steps.
- [ ] PQ SNARK stack: e.g. Plonky3 + Keccak / Poseidon2 vs Spartan + WHIR (hash layer alignment).
- [ ] Optional: cross-check with **JARDIN**-style categorization if they publish comparable numbers.

**Results**

| Experiment | Result | Link / artifact |
|------------|--------|------------------|
| *TBD* | | |

---

## 4. Lattice-based signatures (Falcon & ML-DSA / Dilithium)

**Summary.** Both families verify over **structured lattices** in $\mathbb{Z}_q[x]/(x^n+1)$ (or module structures for ML-DSA) with **small-norm** secrets and rejection sampling or decomposition tricks. NIST standards: **FIPS 206 (FN-DSA / Falcon)** and **FIPS 204 (ML-DSA / Dilithium)**.

### 4.1 Common ZK / SNARK pain points (lattices)

| Issue | Falcon (FN-DSA) | ML-DSA (Dilithium) |
|-------|------------------|---------------------|
| **Arithmetic base** | Odd modulus $q$ (e.g. 12289); NTT-friendly | Different $q$, module rank; more linear algebra |
| **Norm / range checks** | $\ell_2$ / coefficient bounds, dual representations | $\ell_\infty$ bounds, hints / hints verification |
| **Embedding field** | SNARK field $\neq \mathbb{Z}_q$; need gadgets or limbs | Same class of problem; often more constraints |
| **PQ proof stack** | Prefer **transparent** PCS; avoid pairing-only backends for PQ story | Same |

### 4.2 Falcon (FN-DSA-512) — current work

**Repository (Plonky3 port branch):**  
[https://github.com/miha-stopar/falcon.rs/tree/plonky3-port](https://github.com/miha-stopar/falcon.rs/tree/plonky3-port)

**Status (short).**

- Existing **R1CS** (Arkworks) and **Plonk** (Jellyfish) circuits for verification; **Groth16** example uses pairing field (not PQ for the SNARK layer).
- **Plonky3** branch: STARK-style AIR scaffolding; per-NTT-index equation with product + mod-$q$ division witnesses; **not yet** full parity with R1CS (NTT wiring, full norm bounds, dual feasibility in coefficient domain — see crate `falcon-plonky3` README on that branch).

**Roadmap (lattice track).**

1. **Plonky3** — extend AIR toward full Falcon verify (norms, NTT consistency, public input binding).
2. **Spartan + WHIR** — port the same constraint logic to a Spartan-class prover with WHIR (or similar) PCS; compare proof size vs STARK/FRI.
3. **Lattice-native proof systems** — explore arguments whose assumptions align with SIS / Module-LWE (heavier engineering / research).

### 4.3 ML-DSA / Dilithium — planned

**Goals (placeholders).**

- [ ] Choose parameter set (e.g. ML-DSA-44) and reference implementation.
- [ ] Decompose verification: matrix–vector ops mod $q$, decomposition of $t$, hint checks, norm bounds.
- [ ] Estimate R1CS / AIR size vs Falcon at similar classical security narrative.
- [ ] Same PQ SNARK matrix as hash-based section (Plonky3, Spartan+WHIR, …).

**Results**

| Step | Falcon | Dilithium | Notes |
|------|--------|-----------|--------|
| Constraints / trace | *TBD* | *TBD* | |
| Prover time | *TBD* | *TBD* | |
| Proof size | *TBD* | *TBD* | |

---

## 5. PQ-friendly SNARK backends (cross-cutting)

Use this section to fix **one row per backend** so signature schemes are comparable under the same tooling where possible.

| Backend | Setup | Typical field / PCS | PQ narrative | Repo / pointer |
|---------|--------|---------------------|--------------|------------------|
| **Plonky3** (Polygon) | Transparent | e.g. KoalaBear + FRI (+ WHIR integration in ecosystem) | Hash / RS style | [Plonky3](https://github.com/Plonky3/Plonky3) |
| **Spartan + WHIR** | Transparent | WHIR PCS | Hash / RS | e.g. [ProveKit](https://github.com/worldfnd/ProveKit), [Spartan2](https://github.com/microsoft/Spartan2) |
| **Lattice-based SNARKs** | Varies | LWE / SIS-flavored | Strong alignment with lattice sigs; immature tooling | *TBD refs* |

**Benchmark template**

```text
Backend:
Circuit / AIR:
Scheme verified (XMSS / SLH-DSA / Falcon / ML-DSA):
prover_time:
verifier_time:
proof_bytes:
constraints_or_trace:
```

---

## 6. References (standards)

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)  
- NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)  
- NIST FIPS 206 — FN-DSA (Falcon)  
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes (XMSS / LMS)  

---

## 7. Changelog

| Date | Author | Change |
|------|--------|--------|
| *TBD* | | Initial HackMD import from repo doc |

---

*End of document — duplicate into HackMD and replace all `TBD` / checklist items with measured results.*
