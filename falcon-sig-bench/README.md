# falcon-sig-bench

Small binary comparing wall-clock **prove / verify** for:

- Plonky3 full parsed-verify bundle (`falcon-plonky3`)
- Groth16 / R1CS (`falcon-r1cs`)
- UltraPlonk + KZG (`falcon-plonk` + jellyfish)

## Run

```bash
RUSTFLAGS='-C target-cpu=native' cargo run -p falcon-sig-bench --release
```

Example numbers and interpretation (parallel Plonky3 verify, sequential profiling helper, single-STARK trade-offs) live in [`falcon-plonky3/README.md`](../falcon-plonky3/README.md#cross-system-timings-falcon-sig-bench).
