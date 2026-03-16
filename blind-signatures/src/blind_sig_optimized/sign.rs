use super::{BlindSignatureOptimized, BlindedSignatureType, MessageType, PkType, SkType};
use crate::{
    blind_sig_optimized::{BlindedMessageType, EPkType},
    zk::vole_mayo::proof_state::{VOLEMAYOProof, VOLEMAYOProofState},
};
use mayo_c_sys::shake256;
use std::vec;

impl BlindSignatureOptimized {
    /// Computes a blinded message by hashing the message and the pi1 proof from the
    /// zero-knowledge proof together. The blinded message and a proof state are returned.
    ///
    /// # Parameters
    /// - `m`: The message that should be signed
    ///
    /// # Example
    /// ```
    /// use blind_signatures::zk::ZKType;
    /// use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
    ///
    /// let bs = BlindSignatureOptimized::setup(ZKType::FV1_128);
    /// let (pk, sk) = bs.keygen();
    /// let m = b"Hello World!".to_vec();
    /// let mut additional_r: [u8; 32] = [0xff; 32];
    ///
    /// let (bm, state) = bs.sign_1(&m, &mut additional_r);
    /// ```
    pub fn sign_1(
        &self,
        m: &MessageType,
        additional_r: &mut [u8],
    ) -> (BlindedMessageType, VOLEMAYOProofState) {
        let mut state = self.vole_mayo.prove_1(additional_r);
        let proof1_size = self.vole_mayo.vole_mayo_params.proof1_size;
        let mup1 = [m.as_slice(), &state.proof[..proof1_size]].concat();

        let mut h = vec![0u8; self.vole_mayo.vole_mayo_params.h_size];
        unsafe {
            shake256(h.as_mut_ptr(), h.len(), mup1.as_ptr(), mup1.len());
        }
        assert_eq!(state.r.len(), h.len());
        // t = h + r
        let t: Vec<u8> = h
            .iter()
            .zip(state.r.iter())
            .map(|(h_i, r_i)| h_i ^ r_i)
            .collect();

        state.t = t.clone();
        state.h = h;
        state.mu = m.clone();

        (t, state)
    }

    /// Deterministicly compute a MAYO preimage of the provided blinded message.
    ///
    /// # Parameters
    /// - `sk`: the MAYO secret key
    /// - `bm`: the blinded message that acts as the target
    ///
    /// # Example
    /// ```
    /// use blind_signatures::zk::ZKType;
    /// use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
    ///
    /// let bs = BlindSignatureOptimized::setup(ZKType::FV1_128);
    /// let (pk, sk) = bs.keygen();
    /// let m = b"Hello World!".to_vec();
    /// let mut additional_r: [u8; 32] = [0xff; 32];
    ///
    /// let (bm, state) = bs.sign_1(&m, &mut additional_r);
    /// let bsig = bs.sign_2(&sk, &bm);
    /// ```
    pub fn sign_2(&self, sk: &SkType, bm: &BlindedMessageType) -> BlindedSignatureType {
        self.mayo.sample_preimage(sk, bm)
    }

    /// Runs the zk proof using the blinded signature and the initial proof state.
    /// Outputs a proof that can be verified by the verification algorithm
    ///
    /// # Parameters
    /// - `pk`: the mayo public key (compacted)
    /// - `epk`: the extended mayo public key
    /// - `bsig` the MAYO preimage for the blinded message
    /// - `state`: the MAYO proof state from `sign_1`
    ///
    /// # Example
    /// ```
    /// use blind_signatures::zk::ZKType;
    /// use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
    ///
    /// let bs = BlindSignatureOptimized::setup(ZKType::FV1_128);
    /// let (pk, sk) = bs.keygen();
    /// let epk = bs.mayo.expand_pk(&pk);
    /// let m = b"Hello World!".to_vec();
    /// let mut additional_r: [u8; 32] = [0xff; 32];
    ///
    /// let (bm, state) = bs.sign_1(&m, &mut additional_r);
    /// let bsig = bs.sign_2(&sk, &bm);
    /// let sig = bs.sign_3(&pk, &epk, &bsig, state, &mut additional_r);
    /// ```
    pub fn sign_3(
        &self,
        pk: &PkType,
        epk: &EPkType,
        bsig: &BlindedSignatureType,
        state: VOLEMAYOProofState,
        additional_r: &mut [u8],
    ) -> VOLEMAYOProof {
        let t = &state.t;
        let h = &state.h;
        assert!(self.mayo.verify_without_hashing(pk, t, bsig));

        let mut packed_pk = [epk, h.as_slice()].concat();

        let packed_sk = [packed_pk.as_slice(), state.r.as_slice(), bsig].concat();

        self.vole_mayo
            .prove_2(state, &mut packed_pk, &packed_sk, additional_r)
    }
}

#[cfg(test)]
mod test {
    use crate::blind_sig_optimized::BlindSignatureOptimized;
    use std::time::Instant;
    
    /// Ensures that an entire loop of keygen, sign1, sign2, sign3 and verify accepts
    #[test]
    fn test_and_bench_sign_loop_optimized_128sv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::SV1_128);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_128");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-128s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_optimized_128fv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::FV1_128);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_128");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-128f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_optimized_192sv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::SV1_192);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_192");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-192s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_optimized_192fv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::FV1_192);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_192");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-192f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_optimized_256sv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::SV1_256);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_256");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {

            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-256s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_optimized_256fv1() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::FV1_256);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_256");
        // println!("Started warm-up 1 run");
        for _ in 0..10 {
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let bsig = bs.sign_2(&sk, &s1);
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let mut start = Instant::now();
            let (s1, state) = bs.sign_1(&m, &mut additional_r);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &s1);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&epk_u8, &m, &sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "One-More-MAYO-256f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    /// Ensures that not all signatures are accepted
    #[test]
    fn false_signature_rejected() {
        let bs = BlindSignatureOptimized::setup(crate::zk::ZKType::FV1_128);
        let (pk, sk) = bs.keygen();

        let epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        let (s1, state) = bs.sign_1(&m, &mut additional_r);
        let bsig = bs.sign_2(&sk, &s1);

        let mut sig = bs.sign_3(&pk, &epk_u8, &bsig, state, &mut additional_r);
        sig.proof[0] += 1;
        assert!(!bs.verify(&epk_u8, &m, &sig, &mut additional_r))
    }
}
