use crate::zk::{
    ZKType,
    vole_keccak_then_mayo::{
        parameters::VOLEKeccakThenMAYOParameters,
        proof_state::{VOLEKeccakThenMAYOProof, VOLEKeccakThenMAYOProofState},
    },
};

pub mod parameters;
pub mod proof_state;

/// This struct acts as the object callable to utilize the functionalities of [`VOLEKeccakThenMAYO`].
/// With it, you can generate proofs (prove) and validate proofs using
/// different parametersets.
/// It is used within the optimized blind signature [`BlindSignatureConservative`](crate::blind_sig_conservative::BlindSignatureConservative).
pub struct VOLEKeccakThenMAYO {
    pub vole_keccak_then_mayo_params: VOLEKeccakThenMAYOParameters,
}

impl VOLEKeccakThenMAYO {
    /// Given one of the parameter options (defined by [`ZKType`]), fix all functions and
    /// parameters for that specific parameter set.
    pub fn setup(params: ZKType) -> Self {
        VOLEKeccakThenMAYO {
            vole_keccak_then_mayo_params: VOLEKeccakThenMAYOParameters::setup(params),
        }
    }

    /// Computes a [`VOLEKeccakThenMAYOProof`] that contains a proof for:
    /// - the commitment (SHAKE256),
    /// - the target computation (SHAKE256) and
    /// - MAYO.
    pub fn prove(
        &self,
        epk: &mut [u8],
        msg: &mut [u8],
        signature: &mut [u8],
        opening: &mut [u8],
        salt: &mut [u8],
        additional_r: &mut [u8],
    ) -> VOLEKeccakThenMAYOProof {
        let mut state = VOLEKeccakThenMAYOProofState::init(&self.vole_keccak_then_mayo_params);

        let msg_hash = msg;

        assert!(unsafe {
            (self.vole_keccak_then_mayo_params.prove_fn)(
                state.proof.as_mut_ptr(),
                state.random_seed.as_mut_ptr(),
                state.random_seed.len(),
                epk.as_mut_ptr(),
                msg_hash.as_mut_ptr(),
                signature.as_mut_ptr(),
                opening.as_mut_ptr(),
                salt.as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        });

        VOLEKeccakThenMAYOProof::from(state)
    }

    /// Verifies the zk proof for a message, the proof and public keys.
    pub fn verify(
        &self,
        proof: &mut VOLEKeccakThenMAYOProof,
        epk: &mut [u8],
        msg_hash: &mut [u8],
        additional_r: &mut [u8],
    ) -> bool {
        unsafe {
            (self.vole_keccak_then_mayo_params.verify_fn)(
                proof.proof.as_mut_ptr(),
                proof.proof.len(),
                epk.as_mut_ptr(),
                msg_hash.as_mut_ptr(),
                additional_r.as_mut_ptr(),
            )
        }
    }
}
