use super::registration::{REGISTRATION_N1_TAG, REGISTRATION_N2_TAG};
use super::{BlindSignatureConservative, MessageType, PkType, SignatureType};
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
    /// let (s1, _, _, mut state) = bs.sign_1(
    ///     &pk_packed,
    ///     &m,
    ///     &registration.n1,
    ///     &registration.sigj_n1,
    /// );
    /// let bsig = bs.sign_2(&sk, &judge_pk, &s1, &registration);
    ///
    /// let mut sig = bs.sign_3(&mut epk, &bsig, &mut state, &registration, &mut additional_r);
    ///
    /// assert!(bs.verify(&judge_pk, &mut epk, &m, &mut sig, &mut additional_r))
    /// ```
    pub fn verify(
        &self,
        judge_pk: &PkType,
        epk: &mut [u8],
        m: &MessageType,
        sig: &mut SignatureType,
        additional_r: &mut [u8],
    ) -> bool {
        if !self.verify_registration_tagged(
            judge_pk,
            &sig.registration.n1,
            REGISTRATION_N1_TAG,
            &sig.registration.sigj_n1,
        ) {
            return false;
        }
        if !self.verify_registration_tagged(
            judge_pk,
            &sig.registration.n2,
            REGISTRATION_N2_TAG,
            &sig.registration.sigj_n2,
        ) {
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
