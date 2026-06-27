use super::registration::{REGISTRATION_N2_TAG, compute_n1_from_pi_n1, compute_n2};
use super::{
    BlindSignatureConservative, MessageType, PkType, RegistrationBetaType, RegistrationPiN1Type,
    SignatureType,
};
use mayo_c_sys::shake256;

impl BlindSignatureConservative {
    /// Publicly verifies if the signature is valid, i.e., first it hashes the message to
    /// fixed length and then it verifies if the circuit accepts the proof for a signature
    /// and it is connected to the message through a hidden commitment opening `(n1, r)`.
    /// Outputs either `true` or `false`.
    ///
    /// # Parameters
    /// - `epk`: the extended mayo public key
    /// - `judge_pk`: the judge's MAYO public key
    /// - `m`: the message
    /// - `sig`: the signature, i.e., the zk proof
    /// - `pi_n1`: the registration opening mask for `n1`
    /// - `beta`: the registration value equal to `alpha`
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
    /// let registration = bs.reg_user(&judge_output);
    ///
    /// let (s1, n1, sigj_n1, mut state) = bs.sign_1(
    ///     &pk_packed,
    ///     &m,
    ///     &registration.n1,
    ///     &registration.sigj_n1,
    /// );
    /// let bsig = bs.sign_2(&sk, &s1, &n1, &sigj_n1, &judge_pk);
    ///
    /// let mut sig = bs.sign_3(
    ///     &mut epk,
    ///     &bsig,
    ///     &mut state,
    ///     &mut additional_r,
    ///     &registration.pi_n1,
    ///     &registration.n2,
    ///     &registration.sigj_n2,
    /// );
    ///
    /// assert!(bs.verify(
    ///     &judge_pk,
    ///     &mut epk,
    ///     &m,
    ///     &mut sig,
    ///     &mut additional_r,
    ///     &registration.pi_n1,
    ///     &registration.beta,
    /// ))
    /// ```
    pub fn verify(
        &self,
        judge_pk: &PkType,
        epk: &mut [u8],
        m: &MessageType,
        sig: &mut SignatureType,
        additional_r: &mut [u8],
        pi_n1: &RegistrationPiN1Type,
        beta: &RegistrationBetaType,
    ) -> bool {
        if pi_n1.len() != self.lambda / 8 || beta.len() != self.lambda / 4 {
            return false;
        }

        if sig.pi_n1.as_slice() != pi_n1.as_slice() || sig.n2.len() != self.lambda / 8 {
            return false;
        }

        if sig.sigj_n2.len() != self.mayo.mayo_params.sig_bytes + sig.n2.len() + 1 {
            return false;
        }

        let reconstructed_n1 = compute_n1_from_pi_n1(pi_n1, beta);
        let expected_n2 = compute_n2(&reconstructed_n1, beta);
        if sig.n2.as_slice() != expected_n2.as_slice() {
            return false;
        }

        if !self.verify_registration_tagged(judge_pk, &sig.n2, REGISTRATION_N2_TAG, &sig.sigj_n2) {
            return false;
        }

        // 0. hash message to be of fixed length
        let mut msg_hash = vec![0; self.lambda / 8];
        unsafe { shake256(msg_hash.as_mut_ptr(), msg_hash.len(), m.as_ptr(), m.len()) };
        // 1. give it to the circuit
        self.vole_keccak_then_mayo
            .verify(&mut sig.proof, epk, &mut msg_hash, additional_r)
    }
}
