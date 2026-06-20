use crate::{
    commitment::{CommitmentMessageType, CommitmentPseudonymType, CommitmentRandomnessType},
    zk::vole_keccak_then_mayo::{VOLEKeccakThenMAYO, proof_state::VOLEKeccakThenMAYOProof},
};
use mayo_c_sys::mayo::{MAYO, MAYOMessageType, MAYOPkType, MAYOSignatureType, MAYOSkType};

pub mod keygen;
pub mod registration;
pub mod setup;
pub mod sign;
pub mod verify;

// Define the types here to easily change it down the line if needed
pub type SkType = MAYOSkType;
pub type PkType = MAYOPkType;
pub type MessageType = MAYOMessageType;
pub type BlindedMessageType = CommitmentMessageType;
pub type BlindedSignatureType = MAYOSignatureType;
pub type UserStateType = (
    PkType,
    MessageType,
    CommitmentPseudonymType,
    CommitmentRandomnessType,
); //(pk, msg_hash, n1, r)
pub type RegistrationRequestType = BlindedMessageType;
pub type RegistrationNonceType = CommitmentPseudonymType;
pub type RegistrationN2Type = CommitmentPseudonymType;
pub type RegistrationAlphaType = Vec<u8>;
pub type RegistrationBetaType = Vec<u8>;
pub type RegistrationJudgeSignatureType = MAYOSignatureType;
pub type RegistrationPiN1Type = Vec<u8>;
pub type RegistrationStateType = UserStateType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationJudgeOutput {
    pub n1: RegistrationNonceType,
    pub sigj_n1: RegistrationJudgeSignatureType,
    pub pi_n1: RegistrationPiN1Type,
    pub alpha: RegistrationAlphaType,
    pub beta: RegistrationBetaType,
    pub sigj_n2: RegistrationJudgeSignatureType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationSenderOutput {
    pub n1: RegistrationNonceType,
    pub sigj_n1: RegistrationJudgeSignatureType,
    pub pi_n1: RegistrationPiN1Type,
    pub alpha: RegistrationAlphaType,
    pub beta: RegistrationBetaType,
    pub sigj_n2: RegistrationJudgeSignatureType,
    pub n2: RegistrationN2Type,
}

pub struct SignatureType {
    pub n2: RegistrationN2Type,
    pub sigj_n2: RegistrationJudgeSignatureType,
    pub proof: VOLEKeccakThenMAYOProof,
    pub pi_n1: RegistrationPiN1Type,
}

/// This struct contains all the relevant parameters for the blind signature generation.
///
/// # Attributes
/// - `lambda`: the security level
/// - `mayo`: defines the mayo signature scheme
/// - `zk`: defines the zero-knowledge proof system (here VOLEith)
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
/// assert!(bs.verify(&judge_pk, &mut epk, &m, &mut sig, &mut additional_r))
/// ```
pub struct BlindSignatureConservative {
    pub lambda: usize,
    pub mayo: MAYO,
    pub vole_keccak_then_mayo: VOLEKeccakThenMAYO,
}
