# Falcon verification: R1CS constraint reference

This document describes how **constraint counts** are defined for the Arkworks circuits in [`falcon-r1cs`](../README.md), and lists measured sizes for the shipped `ConstraintSynthesizer` implementations.

## What `num_constraints()` means (Arkworks)

`ark_relations::r1cs::ConstraintSystem::num_constraints()` counts **R1CS rows**: each row is one multiplication constraint

\[
(A_i \cdot z) \cdot (B_i \cdot z) = (C_i \cdot z)
\]

over the circuit field **`Fq`** (scalar field of **Edwards BLS12-381**, i.e. the Jubjub-related field used in this crate). Additions are folded into the linear forms \(A_i, B_i, C_i\), so this is the usual **“multiplication count / R1CS rank”** figure used to compare Groth16-style proofs.

Related counters:

- **`num_instance_variables()`** — public inputs (e.g. NTT-domain public key and message hash when allocated as `Input`).
- **`num_witness_variables()`** — private witness columns (coefficients, NTT internals, range proofs, etc.).

## How to reproduce the tables

From the **workspace root** that contains `falcon-r1cs` (same directory as the workspace `Cargo.toml`):

```bash
# Falcon-1024 (default features)
cargo run --release -p falcon-r1cs --example constraint_counts

# Falcon-512
cargo run --release -p falcon-r1cs --example constraint_counts --no-default-features --features=falcon-512
```

The example [`examples/constraint_counts.rs`](../examples/constraint_counts.rs) prints **four** lines:

1. **ntt conversion** — one forward NTT (`NTTPolyVar::ntt_circuit`) for a random coefficient polynomial (micro-benchmark only).
2. **verify with ntt** — [`FalconNTTVerificationCircuit`](../src/circuits/falcon_ntt.rs) (single-limb signature polynomial + `v`, hash/NTT of message as in the README pseudocode).
3. **verify with dual ntt** — [`FalconDualNTTVerificationCircuit`](../src/circuits/falcon_dual_ntt.rs) (dual-limb `sig` and `v`, congruence in the NTT domain, L² bound). This is the closest R1CS analogue to **parsed** Falcon verify used alongside [`falcon-plonky3`](../../falcon-plonky3).
4. **verify with schoolbook** — [`FalconSchoolBookVerificationCircuit`](../src/circuits/falcon_schoolbook.rs) (convolution-style multiply instead of the deferred NTT gadget).

The **third** printed data line (after the header) is **verify with dual ntt**; the **fourth** is schoolbook.

Copy the printed numbers into the tables below when you refresh this document after circuit changes.

## Falcon-1024 (default features)

| Circuit / slice | `#instance` | `#witness` | `#constraints` |
|-----------------|------------:|-----------:|---------------:|
| NTT conversion only | 0 | 29 696 | 30 720 |
| Verify with NTT | 2 049 | 156 724 | 162 870 |
| Verify with dual NTT | *run example* | *run example* | *third printed line* |
| Verify with schoolbook | 2 049 | 1 150 004 | 1 156 150 |

## Falcon-512

| Circuit / slice | `#instance` | `#witness` | `#constraints` |
|-----------------|------------:|-----------:|---------------:|
| NTT conversion only | 0 | 14 848 | 15 360 |
| Verify with NTT | 1 025 | 78 386 | 81 460 |
| Verify with dual NTT | *run example* | *run example* | *third printed line* |
| Verify with schoolbook | 1 025 | 312 882 | 315 956 |

## Relation to `falcon-plonky3` (STARK)

[`falcon-plonky3`](../../falcon-plonky3) reports **AIR primitive identities** and **separate proofs**; that stack is **not** comparable line-for-line to R1CS `num_constraints()`. Order of magnitude for the seven-proof bundle (Falcon-1024) is **on the order of \(10^6\)** primitive `assert_*` scale identities across all STARKs, versus **on the order of \(10^5\)** R1CS rows for a **single** NTT-based Groth16 circuit path at the same parameter set.

## External comparison

An ECC scalar multiplication over the Jubjub curve (≈256-bit) is on the order of **3k** constraints in a typical gadgetization (see the link in the main [`README.md`](../README.md)).
