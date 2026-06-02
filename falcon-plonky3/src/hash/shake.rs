//! SHAKE256 (Falcon) for hash-to-point: native squeeze + Keccak-f step witnesses.

use falcon_rust::{Polynomial, MODULUS, N};
use falcon_rust::shake256_context;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

/// Bytes squeezed before rejection sampling (`N * 3` in Falcon).
pub const SHAKE_SQUEEZE_LEN: usize = N * 3;

/// One Keccak-f input captured immediately before Falcon `process_block`.
#[derive(Clone, Debug)]
pub struct HashToPointResult {
    pub hm: Polynomial,
    pub squeeze: Vec<u8>,
    /// `A` state before each `process_block` (for [`p3_keccak_air`]).
    pub keccak_inputs: Vec<[u64; 25]>,
}

/// `hm = H(msg, nonce)` with squeeze + Keccak step witnesses for in-circuit verification.
pub fn hash_to_point(msg: &[u8], nonce: &[u8]) -> HashToPointResult {
    let squeeze = shake256_context::hash_to_point_squeeze(msg, nonce, SHAKE_SQUEEZE_LEN);
    let hm = Polynomial::from_hash_of_message(msg, nonce);
    debug_assert_eq!(hm.coeff(), &squeeze_to_coeffs(&squeeze));

    let mut st = ShakeState::new();
    st.inject(nonce);
    st.inject(msg);
    st.flip();
    st.extract(&mut vec![0u8; SHAKE_SQUEEZE_LEN]); // record Keccak-f inputs (sponge witness)

    HashToPointResult {
        hm,
        squeeze,
        keccak_inputs: st.keccak_inputs,
    }
}

fn squeeze_to_coeffs(squeeze: &[u8]) -> [u16; N] {
    let mut res = [0u16; N];
    let mut ctr = 0usize;
    let mut i = 0usize;
    while i < N {
        let coeff = (u16::from(squeeze[ctr]) << 8) | u16::from(squeeze[ctr + 1]);
        ctr += 2;
        if coeff < 61445 {
            res[i] = coeff % MODULUS;
            i += 1;
        }
    }
    res
}

struct ShakeState {
    a: [u64; 25],
    dptr: usize,
    keccak_inputs: Vec<[u64; 25]>,
}

const RATE: usize = 136;

impl ShakeState {
    fn new() -> Self {
        Self {
            a: [0u64; 25],
            dptr: 0,
            keccak_inputs: Vec::new(),
        }
    }

    fn dbuf_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.a.as_mut_ptr() as *mut u8, 200) }
    }

    fn inject(&mut self, data: &[u8]) {
        let mut off = 0usize;
        while off < data.len() {
            let room = RATE - self.dptr;
            let take = room.min(data.len() - off);
            let base = self.dptr;
            {
                let dbuf = self.dbuf_mut();
                for u in 0..take {
                    dbuf[base + u] ^= data[off + u];
                }
            }
            self.dptr += take;
            off += take;
            if self.dptr == RATE {
                self.process_block();
                self.dptr = 0;
            }
        }
    }

    fn flip(&mut self) {
        let dptr = self.dptr;
        let dbuf = self.dbuf_mut();
        dbuf[dptr] ^= 0x1f;
        dbuf[135] ^= 0x80;
        self.dptr = RATE;
    }

    fn extract(&mut self, out: &mut [u8]) {
        let mut off = 0usize;
        while off < out.len() {
            if self.dptr == RATE {
                self.process_block();
                self.dptr = 0;
            }
            let room = RATE - self.dptr;
            let take = room.min(out.len() - off);
            let base = self.dptr;
            {
                let dbuf = self.dbuf_mut();
                out[off..off + take].copy_from_slice(&dbuf[base..base + take]);
            }
            self.dptr += take;
            off += take;
        }
    }

    fn process_block(&mut self) {
        self.keccak_inputs.push(self.a);
        falcon_keccakf(&mut self.a);
    }
}

/// Falcon `process_block` (pre/post lane inversions + Keccak-f). Must match Falcon C.
fn falcon_keccakf(a: &mut [u64; 25]) {
    a[1] = !a[1];
    a[2] = !a[2];
    a[8] = !a[8];
    a[12] = !a[12];
    a[17] = !a[17];
    a[20] = !a[20];
    KeccakF.permute_mut(a);
    a[1] = !a[1];
    a[2] = !a[2];
    a[8] = !a[8];
    a[12] = !a[12];
    a[17] = !a[17];
    a[20] = !a[20];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_squeeze_matches_hash_to_point() {
        let msg = b"zk credential presentation";
        let nonce = [7u8; 40];
        let native = Polynomial::from_hash_of_message(msg, &nonce);
        let sim = hash_to_point(msg, &nonce);
        assert_eq!(native, sim.hm);
        assert_eq!(sim.squeeze.len(), SHAKE_SQUEEZE_LEN);
    }
}
