use super::{BlindSignatureConservativeRain, MessageType, SignatureType};
use mayo_c_rain_sys::shake256;

impl BlindSignatureConservativeRain {
    /// Publicly verifies if the signature is valid, i.e., first it hashes the message to
    /// fixed length and then it verifies if the circuit accepts the proof for a signature
    /// and it is connected to the message.
    /// Outputs either `true` or `false`.
    ///
    /// # Parameters
    /// - `epk`: the extended mayo public key
    /// - `m`: the message
    /// - `sig`: the signature, i.e., the zk proof
    ///
    /// # Example
    /// ```
    /// use blind_signatures_conservative_rain::zk::ZKType;
    /// use blind_signatures_conservative_rain::blind_sig_conservative_rain::BlindSignatureConservativeRain;
    ///
    /// let bs = BlindSignatureConservativeRain::setup(ZKType::FV2_128);
    /// let (pk_packed, sk) = bs.keygen();
    ///
    /// let mut epk = bs.mayo.expand_pk(&pk_packed);
    ///
    /// let m = b"Hello World!".to_vec();
    /// let mut additional_r: [u8; 32] = [0xff; 32];
    ///
    /// let (s1, mut state) = bs.sign_1(&m);
    /// let bsig = bs.sign_2(&sk, &s1);
    ///
    /// let mut sig = bs.sign_3(&pk_packed, &mut epk, &bsig, &mut state, &mut additional_r);
    ///
    /// assert!(bs.verify(&mut epk, &m, &mut sig, &mut additional_r))
    /// ```
    pub fn verify(
        &self,
        epk: &mut [u8],
        m: &MessageType,
        sig: &mut SignatureType,
        additional_r: &mut [u8],
    ) -> bool {
        // 0. hash message to be of fixed length
        let mut msg_hash = vec![0; self.lambda / 8];
        unsafe { shake256(msg_hash.as_mut_ptr(), msg_hash.len(), m.as_ptr(), m.len()) };
        // 1. give it to the circuit
        self.vole_rain_then_mayo
            .verify(sig, epk, &mut msg_hash, additional_r)
    }
}
