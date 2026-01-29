use crate::{
    commitment::{CommitmentMessageType, CommitmentRandomnessType},
    zk::vole_rain_then_mayo::{VOLERainThenMAYO, proof_state::VOLERainThenMAYOProof},
};
use mayo_c_rain_sys::mayo::{MAYO, MAYOMessageType, MAYOPkType, MAYOSignatureType, MAYOSkType};

pub mod keygen;
pub mod setup;
pub mod sign;
pub mod verify;

// Define the types here to easily change it down the line if needed
pub type SkType = MAYOSkType;
pub type PkType = MAYOPkType;
pub type MessageType = MAYOMessageType;
pub type SignatureType = VOLERainThenMAYOProof;
pub type BlindedMessageType = CommitmentMessageType;
pub type BlindedSignatureType = MAYOSignatureType;
pub type UserStateType = (MessageType, CommitmentRandomnessType); //(pk, m, r)

/// This struct contains all the relevant parameters for the blind signature generation.
///
/// # Attributes
/// - `lambda`: the security level
/// - `mayo`: defines the mayo signature scheme
/// - `zk`: defines the zero-knowledge proof system (here VOLEith)
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
pub struct BlindSignatureConservativeRain {
    pub lambda: usize,
    pub mayo: MAYO,
    pub vole_rain_then_mayo: VOLERainThenMAYO,
}
