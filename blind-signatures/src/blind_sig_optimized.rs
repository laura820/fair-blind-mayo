//! The optimized blind signature construction using MAYO.
//!
//! It is structured as follows:
//! there are 4 subfolders: setup, keygen, sign and verify
//!
//! Each of them carries the implementation from the name-shared functions.
//! They utilize the implementations of [`VOLEMAYO`] and
//! [`MAYO`] that are linked to the implementations in C++ and C.

use crate::zk::vole_mayo::{VOLEMAYO, proof_state::VOLEMAYOProof};
use mayo_c_sys::mayo::{
    MAYO, MAYOEPkType, MAYOMessageType, MAYOPkType, MAYOSignatureType, MAYOSkType,
};

mod keygen;
mod setup;
mod sign;
mod verify;

/// MAYO compressed public key
pub type PkType = MAYOPkType;
/// MAYO expanded public key
pub type EPkType = MAYOEPkType;
/// MAYO secret key
pub type SkType = MAYOSkType;
pub type MessageType = MAYOMessageType;
/// MAYO signature
pub type BlindedMessageType = Vec<u8>; // of length m_digest
pub type BlindedSignatureType = MAYOSignatureType;
/// VOLEMAYO proof
pub type SignatureType = VOLEMAYOProof;

/// This struct contains all the relevant parameters for the blind signature generation.
///
/// # Attributes
/// - `mayo`: defines the mayo signature scheme
/// - `zk`: defines the zero-knowledge proof system (here VOLEith)
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
pub struct BlindSignatureOptimized {
    pub mayo: MAYO,
    pub vole_mayo: VOLEMAYO,
}
