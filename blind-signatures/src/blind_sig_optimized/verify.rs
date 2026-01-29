use super::{BlindSignatureOptimized, MessageType, SignatureType};
use mayo_c_sys::shake256;

impl BlindSignatureOptimized {
    /// Publicly verifies if the signature is valid, i.e., first it recomputes the hash
    /// from sign1 and then it verifies if the circuit accepts the proof for a signature
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
    /// assert!(bs.verify(&epk, &m, &sig, &mut additional_r))
    /// ```
    pub fn verify(
        &self,
        epk: &[u8],
        m: &MessageType,
        sig: &SignatureType,
        additional_r: &mut [u8],
    ) -> bool {
        let proof1_size = self.vole_mayo.vole_mayo_params.proof1_size;
        let mup1 = [&m[..], &sig.proof[..proof1_size]].concat();

        let mut h = vec![0u8; self.vole_mayo.vole_mayo_params.h_size];
        unsafe {
            shake256(h.as_mut_ptr(), h.len(), mup1.as_ptr(), mup1.len());
        }

        let packed_pk = [epk, h.as_slice()].concat();
        self.vole_mayo.verify(sig, &packed_pk, additional_r)
    }
}
