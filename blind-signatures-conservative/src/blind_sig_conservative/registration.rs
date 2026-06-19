use super::{
    BlindSignatureConservative, PkType, RegistrationJudgeOutput, RegistrationSenderOutput, SkType,
};
use rand::Rng;

pub(crate) const REGISTRATION_N1_TAG: bool = false;
pub(crate) const REGISTRATION_N2_TAG: bool = true;

fn tagged_registration_message(nonce: &[u8], tag_bit: bool) -> Vec<u8> {
    let mut message = Vec::with_capacity(nonce.len() + 1);
    message.extend_from_slice(nonce);
    // MAYO signs byte slices, so the appended bit is packed as the most
    // significant bit of the final byte and padded with zeroes.
    message.push(if tag_bit { 0b1000_0000 } else { 0 });
    message
}

fn compute_pi_n1(n1: &[u8], alpha: &[u8]) -> Vec<u8> {
    assert!(alpha.len() >= n1.len());
    alpha[..n1.len()]
        .iter()
        .zip(n1.iter())
        .map(|(alpha_byte, n1_byte)| *alpha_byte ^ *n1_byte)
        .collect()
}

fn compute_n2(n1: &[u8], alpha: &[u8]) -> Vec<u8> {
    assert!(alpha.len() >= 2 * n1.len());
    alpha[n1.len()..(2 * n1.len())]
        .iter()
        .zip(n1.iter())
        .map(|(alpha_byte, n1_byte)| *alpha_byte ^ *n1_byte)
        .collect()
}

impl BlindSignatureConservative {
    pub(crate) fn verify_registration_tagged(
        &self,
        judge_pk: &PkType,
        nonce: &[u8],
        tag_bit: bool,
        signature: &[u8],
    ) -> bool {
        let message = tagged_registration_message(nonce, tag_bit);
        self.mayo.verify(judge_pk, &message, &signature.to_vec())
    }

    /// Runs the judge's side of the registration protocol.
    ///
    /// The judge samples a fresh `n1`, samples `alpha` and `beta`, derives
    /// `pi_n1` from `n1` and the first half of `alpha`, derives `n2` from
    /// `n1` and the second half of `alpha`, signs `n1 || 0` and `n2 || 1`
    /// using one-bit tags packed into the final message byte, and sends all
    /// public registration values back to the sender.
    /// The sender will use this output when building the registration request.
    ///
    /// # Example
    /// ```no_run
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    /// use blind_signatures_conservative::zk::ZKType;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV1_128);
    /// let (_judge_pk, judge_sk) = bs.keygen();
    ///
    /// let judge_output = bs.reg_judge(&judge_sk);
    /// ```
    pub fn reg_judge(&self, judge_sk: &SkType) -> RegistrationJudgeOutput {
        let mut rng = rand::rng();
        let n1: Vec<u8> = (0..(self.lambda / 8)).map(|_| rng.random()).collect();
        let alpha: Vec<u8> = (0..(self.lambda / 4)).map(|_| rng.random()).collect();
        let pi_n1 = compute_pi_n1(&n1, &alpha);
        let beta: Vec<u8> = (0..(self.lambda / 2)).map(|_| rng.random()).collect();
        let n2 = compute_n2(&n1, &alpha);
        let sigj_n1 = self.mayo.sign(
            judge_sk,
            &tagged_registration_message(&n1, REGISTRATION_N1_TAG),
        );
        let sigj_n2 = self.mayo.sign(
            judge_sk,
            &tagged_registration_message(&n2, REGISTRATION_N2_TAG),
        );

        RegistrationJudgeOutput {
            n1,
            sigj_n1,
            pi_n1,
            alpha,
            beta,
            sigj_n2,
        }
    }

    /// Runs the sender's side of the registration protocol.
    ///
    /// The sender receives the judge-provided `n1`, `sigj_n1`, `pi_n1`,
    /// `alpha`, `beta` and `sigj_n2`, derives `n2` from `n1` and the second
    /// half of `alpha`, and stores them in the registration output that will
    /// be passed to `sign_1`.
    ///
    /// # Example
    /// ```no_run
    /// use blind_signatures_conservative::blind_sig_conservative::BlindSignatureConservative;
    /// use blind_signatures_conservative::zk::ZKType;
    ///
    /// let bs = BlindSignatureConservative::setup(ZKType::FV1_128);
    /// let (_judge_pk, judge_sk) = bs.keygen();
    /// let judge_output = bs.reg_judge(&judge_sk);
    /// let sender_output = bs.reg_sender(&judge_output);
    /// ```
    pub fn reg_sender(&self, judge_output: &RegistrationJudgeOutput) -> RegistrationSenderOutput {
        assert_eq!(judge_output.n1.len(), self.lambda / 8);
        assert_eq!(judge_output.alpha.len(), self.lambda / 4);
        assert_eq!(judge_output.beta.len(), self.lambda / 2);
        assert_eq!(judge_output.pi_n1.len(), judge_output.n1.len());
        assert_eq!(
            judge_output.pi_n1.as_slice(),
            compute_pi_n1(&judge_output.n1, &judge_output.alpha).as_slice()
        );
        assert_eq!(
            judge_output.sigj_n1.len(),
            self.mayo.mayo_params.sig_bytes + judge_output.n1.len() + 1
        );
        let n2 = compute_n2(&judge_output.n1, &judge_output.alpha);
        assert_eq!(
            judge_output.sigj_n2.len(),
            self.mayo.mayo_params.sig_bytes + n2.len() + 1
        );

        RegistrationSenderOutput {
            n1: judge_output.n1.clone(),
            sigj_n1: judge_output.sigj_n1.clone(),
            pi_n1: judge_output.pi_n1.clone(),
            alpha: judge_output.alpha.clone(),
            beta: judge_output.beta.clone(),
            sigj_n2: judge_output.sigj_n2.clone(),
            n2,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{REGISTRATION_N1_TAG, REGISTRATION_N2_TAG};
    use crate::blind_sig_conservative::BlindSignatureConservative;

    #[test]
    fn registration_loop_accepts() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let bs = BlindSignatureConservative::setup(crate::zk::ZKType::FV1_128);
                let (pk, sk) = bs.keygen();
                let (judge_pk, judge_sk) = bs.keygen();
                assert_ne!(pk, judge_pk);

                let mut epk = bs.mayo.expand_pk(&pk);
                let mut additional_r: [u8; 32] = [0xff; 32];
                let registration_message = b"user registration".to_vec();

                let judge_output = bs.reg_judge(&judge_sk);
                assert_eq!(judge_output.n1.len(), bs.lambda / 8);
                assert_eq!(
                    judge_output.sigj_n1.len(),
                    bs.mayo.mayo_params.sig_bytes + judge_output.n1.len() + 1
                );
                assert_eq!(judge_output.pi_n1.len(), judge_output.n1.len());
                assert_eq!(judge_output.alpha.len(), bs.lambda / 4);
                assert_eq!(judge_output.beta.len(), bs.lambda / 2);
                let expected_pi_n1: Vec<u8> = judge_output.alpha[..judge_output.n1.len()]
                    .iter()
                    .zip(judge_output.n1.iter())
                    .map(|(alpha_byte, n1_byte)| *alpha_byte ^ *n1_byte)
                    .collect();
                assert_eq!(judge_output.pi_n1, expected_pi_n1);
                let expected_n2: Vec<u8> = judge_output.alpha
                    [judge_output.n1.len()..(2 * judge_output.n1.len())]
                    .iter()
                    .zip(judge_output.n1.iter())
                    .map(|(alpha_byte, n1_byte)| *alpha_byte ^ *n1_byte)
                    .collect();
                assert_eq!(
                    judge_output.sigj_n2.len(),
                    bs.mayo.mayo_params.sig_bytes + expected_n2.len() + 1
                );
                assert!(bs.verify_registration_tagged(
                    &judge_pk,
                    &judge_output.n1,
                    REGISTRATION_N1_TAG,
                    &judge_output.sigj_n1
                ));
                assert!(bs.verify_registration_tagged(
                    &judge_pk,
                    &expected_n2,
                    REGISTRATION_N2_TAG,
                    &judge_output.sigj_n2
                ));
                let (wrong_judge_pk, _) = bs.keygen();
                assert!(!bs.verify_registration_tagged(
                    &wrong_judge_pk,
                    &judge_output.n1,
                    REGISTRATION_N1_TAG,
                    &judge_output.sigj_n1
                ));
                assert!(!bs.verify_registration_tagged(
                    &wrong_judge_pk,
                    &expected_n2,
                    REGISTRATION_N2_TAG,
                    &judge_output.sigj_n2
                ));

                let sender_output = bs.reg_sender(&judge_output);
                assert_eq!(sender_output.n1.as_slice(), judge_output.n1.as_slice());
                assert_eq!(
                    sender_output.sigj_n1.as_slice(),
                    judge_output.sigj_n1.as_slice()
                );
                assert_eq!(
                    sender_output.sigj_n2.as_slice(),
                    judge_output.sigj_n2.as_slice()
                );
                assert_eq!(
                    sender_output.pi_n1.as_slice(),
                    judge_output.pi_n1.as_slice()
                );
                assert_eq!(
                    sender_output.alpha.as_slice(),
                    judge_output.alpha.as_slice()
                );
                assert_eq!(sender_output.beta.as_slice(), judge_output.beta.as_slice());
                assert_eq!(sender_output.n2, expected_n2);

                let (request, n1, sigj_n1, mut state) = bs.sign_1(
                    &pk,
                    &registration_message,
                    &sender_output.n1,
                    &sender_output.sigj_n1,
                );
                assert_eq!(n1.as_slice(), judge_output.n1.as_slice());
                assert_eq!(sigj_n1.as_slice(), judge_output.sigj_n1.as_slice());
                assert_eq!(state.2.as_slice(), judge_output.n1.as_slice());

                let response = bs.sign_2(
                    &sk,
                    &request,
                    &sender_output.n1,
                    &sender_output.sigj_n1,
                    &judge_pk,
                );
                let mut credential = bs.sign_3(
                    &mut epk,
                    &response,
                    &mut state,
                    &sender_output,
                    &mut additional_r,
                );

                assert!(bs.verify(
                    &judge_pk,
                    &mut epk,
                    &registration_message,
                    &mut credential,
                    &mut additional_r
                ));
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
