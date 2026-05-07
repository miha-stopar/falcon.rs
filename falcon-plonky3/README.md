# falcon-plonky3

Plonky3 STARK scaffolding for Falcon signature verification (see [`falcon-rust`](../falcon-rust) for the lattice scheme and [`falcon-r1cs`](../falcon-r1cs/src/circuits/falcon_dual_ntt.rs) for the closest R1CS).

## Trace layout (per row)

Rows are indexed by NTT coefficient $i = 0 \ldots N-1$ (with $N = 512$ or $1024$). One row = one NTT index.

### Preprocessed trace (2 columns)

Committed once per statement; intended to correspond to **public** Falcon data (same role as `pk_ntt` / `hm_ntt` inputs in Groth16 examples).

| Col | Name     | Meaning |
|-----|----------|---------|
| 0   | `pk_ntt` | Public key polynomial in **NTT** form, coeff $i$ over $\mathbb{Z}_q$ |
| 1   | `hm_ntt` | Message-hash polynomial `hm` in **NTT** form, coeff $i$ |

### Main trace (36 columns)

Private witness per row. Coefficients are still **Falcon residues mod** `q = 12289`, embedded into KoalaBear for the STARK.

| Col(s) | Name | Meaning |
|--------|------|---------|
| 0–1 | `sig_pos_ntt`, `sig_neg_ntt` | Dual-limb NTT of signature polynomial (see dual path in [`verify_parsed_sig`](../falcon-rust/src/structs/pk.rs)) |
| 2–3 | `v_pos_ntt`, `v_neg_ntt` | Dual-limb NTT of $v = hm - s\cdot pk$ |
| 4–5 | `lhs_mod`, `rhs_mod` | Residues mod $q$ of the two sides of the dual-NTT congruence (must agree) |
| 6–7 | `prod_sig_pos_pk`, `prod_sig_neg_pk` | Integer products `sig_pos·pk` and `sig_neg·pk` (as integers $< q^2$), embedded in KoalaBear |
| 8–21 | `quot_l_bits[0..14]` | Little-endian bits of quotient `quot_l` in `sum_left = quot_l·q + lhs_mod` |
| 22–35 | `quot_r_bits[0..14]` | Bits for `quot_r` in `sum_right = quot_r·q + rhs_mod` |

### Diagram (one row)

```text
Preprocessed                          Main (witness)
+----------------+                    +------------------------------------------+
| pk_ntt[i]      |                    | sig_pos_ntt  sig_neg_ntt             |
| hm_ntt[i]      |                    | v_pos_ntt    v_neg_ntt               |
+----------------+                    | lhs_mod      rhs_mod                 |
        |                             | prod_sp_pk   prod_sn_pk              |
        +------------------------------| quot_l_bits[14] quot_r_bits[14]      |
                                      +------------------------------------------+
```

Mermaid (dependency view for enforced identities):

```mermaid
flowchart LR
  subgraph prep [Preprocessed]
    pk[pk_ntt]
    hm[hm_ntt]
  end
  subgraph main [Main]
    sp[sig_pos]
    sn[sig_neg]
    vp[v_pos]
    vn[v_neg]
    lhs[lhs_mod]
    rhs[rhs_mod]
    psp[prod_sp]
    psn[prod_sn]
    ql[quot_l bits]
    qr[quot_r bits]
  end
  pk --> psp
  sp --> psp
  pk --> psn
  sn --> psn
  hm --> sumL[sum_left]
  vn --> sumL
  psn --> sumL
  vp --> sumR[sum_right]
  psp --> sumR
  sumL --> divL["sum_left = ql*q + lhs"]
  sumR --> divR["sum_right = qr*q + rhs"]
  ql --> divL
  lhs --> divL
  qr --> divR
  rhs --> divR
  lhs --- rhs
```

## What is proved today

For each row $i$, the AIR enforces:

1. **`prod_sig_pos_pk = sig_pos_ntt · pk_ntt`** and **`prod_sig_neg_pk = sig_neg_ntt · pk_ntt`** using **KoalaBear multiplication** (sound here because true products are $< q^2 < 2^{31}$ and lie below the KoalaBear prime, so they agree with integer multiplication).
2. **`sum_left = hm_ntt + v_neg_ntt + prod_sig_neg_pk`** and **`sum_right = v_pos_ntt + prod_sig_pos_pk`** (integer sums, same bound).
3. **Euclidean division mod $q$** via witnesses `lhs_mod`, `quot_l` (from bits), `rhs_mod`, `quot_r`:
   - `sum_left - lhs_mod - quot_l·q = 0`
   - `sum_right - rhs_mod - quot_r·q = 0`
   with `quot_l`, `quot_r` each **14-bit** (boolean bit constraints).
4. **`lhs_mod = rhs_mod`**.

This matches the **per-index congruence** proved in [`FalconDualNTTVerificationCircuit`](../falcon-r1cs/src/circuits/falcon_dual_ntt.rs) (modulo the R1CS `mod_q` gadget encoding), **without** yet proving:

- NTT layers (`sig_ntt` / `v_ntt` are correct NTTs of coefficient-domain limbs),
- dual feasibility `pos·neg = 0` in the **coefficient** domain,
- Falcon **norm / range** bounds.

## Field sizes: KoalaBear vs BLS12-381 `Fr`

| Field | Typical size | Role in this repo |
|-------|----------------|-------------------|
| **KoalaBear** (Plonky3) | ~31-bit prime | STARK trace / constraints |
| **BLS12-381 scalar (`Fr`)** | ~256-bit | Groth16 / Arkworks (`falcon-r1cs` examples) |
| **Falcon modulus $q$** | `12289` | Coefficient ring $\mathbb{Z}_q$ |

Yes — **KoalaBear is vastly smaller than `Fr`**. That is **not** a problem for **embedding Falcon coefficients** ($< q$) or the **products** we use ($< q^2$): both fit comfortably below the KoalaBear prime, so those values behave like integers and **native KoalaBear `+` / `×`** match integer arithmetic **as long as** every intermediate you care about stays $< p_{\text{KoalaBear}}$.

What **would** be wrong is to confuse **“multiply in KoalaBear”** with **“multiply in $\mathbb{Z}_q$”** for *general* formulas; we only use KoalaBear `×` where the **integer product** is provably small enough to avoid modular wraparound, and we route modular reduction through **explicit $q$-division identities** with bounded quotients.

## Running tests

```bash
RUSTFLAGS="-C target-cpu=native" cargo test -p falcon-plonky3 --release
```
