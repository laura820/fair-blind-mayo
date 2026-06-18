extern crate rand;
use super::registration::{REGISTRATION_N1_TAG, REGISTRATION_N2_TAG};
use super::{
    BlindSignatureConservative, BlindedMessageType, BlindedSignatureType, MessageType, PkType,
    RegistrationSenderOutput, SignatureType, SkType, UserStateType,
};
use crate::commitment::shake256_commitment;
use mayo_c_sys::shake256;
use rand::Rng;

impl BlindSignatureConservative {
    /// Computes a blinded message using a commitment scheme, here a hash-commitment using SHAKE256.
    ///
    /// # Params:
    /// - `m`: The message that should be blinded
    /// - `registration`: The sender registration output containing the judge-provided `n1`
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative::zk::ZKType;
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV2_128);
    /// let (pk, sk) = bs.keygen();
    /// let m = b"Hello World!".to_vec();
    /// let (_judge_pk, judge_sk) = bs.keygen();
    /// let judge_output = bs.reg_judge(&judge_sk);
    /// let registration = bs.reg_sender(&judge_output);
    ///
    /// let (bm, state) = bs.sign_1(&m, &registration);
    /// ```
    ///
    /// Returns a blinded message (commitment) and a user state that consists of:
    /// the (hashed) message, the commitment pseudonym and the commitment randomness.
    pub fn sign_1(
        &self,
        m: &MessageType,
        registration: &RegistrationSenderOutput,
    ) -> (BlindedMessageType, UserStateType) {
        assert_eq!(registration.n1.len(), self.lambda / 8);
        assert_eq!(registration.alpha.len(), self.lambda / 4);
        assert_eq!(registration.beta.len(), self.lambda / 2);
        assert_eq!(registration.pi_n1.len(), registration.n1.len());
        assert_eq!(registration.n2.len(), registration.n1.len());
        assert_eq!(
            registration.sigj_n1.len(),
            self.mayo.mayo_params.sig_bytes + registration.n1.len() + 1
        );
        assert_eq!(
            registration.sigj_n2.len(),
            self.mayo.mayo_params.sig_bytes + registration.n2.len() + 1
        );

        let mut rng = rand::rng();
        let r = (0..(self.lambda / 8)).map(|_| rng.random()).collect();

        let mut msg_hash = vec![0; self.lambda / 8];
        unsafe { shake256(msg_hash.as_mut_ptr(), msg_hash.len(), m.as_ptr(), m.len()) };

        let com = shake256_commitment(
            &msg_hash,
            &registration.n1,
            &r,
            self.mayo.mayo_params.m_digest_bytes,
        );

        (
            com,
            (
                msg_hash,
                registration.n1.clone(),
                r,
                registration.alpha.clone(),
                registration.beta.clone(),
                registration.sigj_n1.clone(),
                registration.sigj_n2.clone(),
                registration.pi_n1.clone(),
                registration.n2.clone(),
            ),
        )
    }

    /// Deterministicly compute a MAYO signature of the provided blinded message.
    /// The MAYO signature takes in fixed length messages.
    ///
    /// # Parameters
    /// - `sk`: the MAYO secret key used by the signer
    /// - `judge_pk`: the MAYO public key used to verify the judge registration
    /// - `bm`: the blinded message (the commitment)
    /// - `registration`: the judge registration output copied by the sender
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative::zk::ZKType;
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV2_128);
    /// let (pk, sk) = bs.keygen();
    /// let m = b"Hello World!".to_vec();
    /// let (judge_pk, judge_sk) = bs.keygen();
    /// let judge_output = bs.reg_judge(&judge_sk);
    /// let registration = bs.reg_sender(&judge_output);
    ///
    /// let (bm, state) = bs.sign_1(&m, &registration);
    /// let bsig = bs.sign_2(&sk, &judge_pk, &bm, &registration);
    /// ```
    pub fn sign_2(
        &self,
        sk: &SkType,
        judge_pk: &PkType,
        bm: &BlindedMessageType,
        registration: &RegistrationSenderOutput,
    ) -> BlindedSignatureType {
        assert!(self.verify_registration_tagged(
            judge_pk,
            &registration.n1,
            REGISTRATION_N1_TAG,
            &registration.sigj_n1
        ));
        assert!(self.verify_registration_tagged(
            judge_pk,
            &registration.n2,
            REGISTRATION_N2_TAG,
            &registration.sigj_n2
        ));
        self.mayo.sign_fixed_length(sk, bm)
    }

    /// Runs the zk proof using the blinded signature, the initial proof state
    /// and the commitment opening `(n1, r)`.
    /// Outputs a proof that can be verified by the verification algorithm.
    ///
    /// # Parameters
    /// - `pk`: the compacted mayo public key
    /// - `epk`: the extended mayo public key
    /// - `bsig` the MAYO preimage for the blinded message
    /// - `state`: the MAYO proof state from `sign_1`
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative::zk::ZKType;
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV2_256);
    /// let (pk_packed, sk) = bs.keygen();
    ///
    /// let mut epk = bs.mayo.expand_pk(&pk_packed);
    ///
    /// let m = b"Hello World!".to_vec();
    /// let mut additional_r: [u8; 32] = [0xff; 32];
    /// let (judge_pk, judge_sk) = bs.keygen();
    /// let judge_output = bs.reg_judge(&judge_sk);
    /// let registration = bs.reg_sender(&judge_output);
    ///
    /// let (s1, mut state) = bs.sign_1(&m, &registration);
    /// let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
    ///
    /// let mut sig = bs.sign_3(&pk_packed, &mut epk, &bsig, &mut state, &mut additional_r);
    /// ```
    pub fn sign_3(
        &self,
        pk: &PkType,
        epk: &mut [u8],
        bsig: &BlindedSignatureType,
        state: &mut UserStateType,
        additional_r: &mut [u8],
    ) -> SignatureType {
        let (msg_hash, n1, rand, alpha, beta, sigj_n1, sigj_n2, pi_n1, n2) = state;

        assert_eq!(msg_hash.len(), self.lambda / 8);
        assert_eq!(n1.len(), self.lambda / 8);
        assert_eq!(rand.len(), self.lambda / 8);
        assert_eq!(alpha.len(), self.lambda / 4);
        assert_eq!(beta.len(), self.lambda / 2);
        assert_eq!(
            sigj_n1.len(),
            self.mayo.mayo_params.sig_bytes + n1.len() + 1
        );
        assert_eq!(
            sigj_n2.len(),
            self.mayo.mayo_params.sig_bytes + n2.len() + 1
        );
        assert_eq!(pi_n1.len(), n1.len());
        assert_eq!(n2.len(), n1.len());

        // 0. recompute blinded message
        let com = shake256_commitment(msg_hash, n1, rand, self.mayo.mayo_params.m_digest_bytes);
        // 1. verify the mayo signature
        assert!(self.mayo.verify_fixed_length(pk, &com, bsig));
        // 2. retrieve salt and signature from blinded signature
        let mut signature = bsig[..(bsig.len() - self.mayo.mayo_params.salt_bytes)].to_vec();
        let mut salt = bsig[(bsig.len() - self.mayo.mayo_params.salt_bytes)..].to_vec();
        let mut opening = Vec::with_capacity(n1.len() + rand.len());
        opening.extend_from_slice(n1);
        opening.extend_from_slice(rand);
        // 3. compute the proof
        let proof = self.vole_keccak_then_mayo.prove(
            epk,
            msg_hash,
            &mut signature,
            &mut opening,
            &mut salt,
            additional_r,
        );

        SignatureType {
            proof,
            registration: RegistrationSenderOutput {
                n1: n1.clone(),
                sigj_n1: sigj_n1.clone(),
                pi_n1: pi_n1.clone(),
                alpha: alpha.clone(),
                beta: beta.clone(),
                sigj_n2: sigj_n2.clone(),
                n2: n2.clone(),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use crate::blind_sig_conservative::BlindSignatureConservative;
    use std::time::Instant;

    /// Ensures that an entire loop of keygen, sign1, sign2, sign3 and verify accepts
    #[test]
    fn test_and_bench_sign_loop_conservative_128sv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::SV1_128);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_128");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-128s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_conservative_128fv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::FV1_128);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_128");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-128f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_conservative_192sv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::SV1_192);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_192");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-192s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_conservative_192fv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::FV1_192);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_192");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-192f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_conservative_256sv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::SV1_256);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching SV1_256");
        // println!("Started warm-up 10 runs");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-256s - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
                );
            }
        }

        // println!("sign 1 Time elapsed: {} ms", sign1 / iter);
        // println!("sign 2 Time elapsed: {} ms", sign2 / iter);
        // println!("sign 3 Time elapsed: {} ms", sign3 / iter);
        // println!("verify Time elapsed: {} ms", verify / iter);
    }

    #[test]
    fn test_and_bench_sign_loop_conservative_256fv1() {
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::FV1_256);
        let (pk, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk_u8 = bs.mayo.expand_pk(&pk);

        let m = b"Hello World!".to_vec();
        let mut additional_r: [u8; 32] = [0xff; 32];

        // println!("Benching FV1_256");
        // println!("Started warm-up 10 run");
        for _ in 0..10 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
        }

        let mut sign1 = 0.0;
        let mut sign2 = 0.0;
        let mut sign3 = 0.0;
        let mut verify = 0.0;
        let iter = 20.0;

        // println!("Bench started 0 / {:?}", iter);
        for i in 0..iter as i32 {
            let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
            let mut start = Instant::now();
            let (s1, mut state) = bs.sign_1(&m, &registration);
            let mut duration = start.elapsed();
            sign1 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
            duration = start.elapsed();
            sign2 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            let mut sig = bs.sign_3(&pk, &mut epk_u8, &bsig, &mut state, &mut additional_r);
            duration = start.elapsed();
            sign3 += duration.as_micros() as f64 / 1_000.0;

            start = Instant::now();
            assert!(bs.verify(&judge_pk, &mut epk_u8, &m, &mut sig, &mut additional_r));
            duration = start.elapsed();
            verify += duration.as_micros() as f64 / 1_000.0;

            // if i == 0 {
            //     println!("s1 + bsig len {:?}", (s1.len() + bsig.len()) as f64 / 1024.0);
            //     println!("sig len {:?}", sig.proof.proof.len() as f64 / 1024.0);
            // }

            // if (i + 1) % 10 == 0 {
            //     println!("{:?} / {:?} runs done...", i + 1, iter);
            // }

            if i == (iter as i32) - 1 {
                println!(
                    "SHAKE256+MAYO-256f - {}, {}, {}, {}, {}, {}",
                    sign1 / iter,
                    sign2 / iter,
                    sign3 / iter,
                    verify / iter,
                    (s1.len() + bsig.len()) as f64 / 1024.0,
                    sig.proof.proof.len() as f64 / 1024.0
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
        let bs = BlindSignatureConservative::setup(crate::zk::ZKType::FV1_128);
        let (pk_packed, sk) = bs.keygen();
        let (judge_pk, judge_sk) = bs.keygen();

        let mut epk = bs.mayo.expand_pk(&pk_packed);

        let mut additional_r: [u8; 32] = [0xff; 32];
        let m = b"Hello World!".to_vec();

        let registration = bs.reg_sender(&bs.reg_judge(&judge_sk));
        let (s1, mut state) = bs.sign_1(&m, &registration);
        let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);

        let mut sig = bs.sign_3(&pk_packed, &mut epk, &bsig, &mut state, &mut additional_r);
        sig.proof.proof[0] += 1;

        assert!(!bs.verify(&judge_pk, &mut epk, &m, &mut sig, &mut additional_r))
    }
}
