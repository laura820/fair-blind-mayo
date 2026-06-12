//! The commitment scheme used within the blind signature.

use mayo_c_sys::shake256;

pub type CommitmentType = Vec<u8>;
pub type CommitmentMessageType = Vec<u8>;
pub type CommitmentPseudonymType = Vec<u8>;
pub type CommitmentRandomnessType = Vec<u8>;

pub const SHAKE256_RATE_BYTES: usize = 136;

/// Hash-commitments using Keccak's-SHAKE256.
/// The inputs are concatenated and its hash value is returned
///
/// # Params
/// - `m`: the message of fixed length lambda
/// - `n1`: the pseudonym
/// - `r`: the randomness of fixed length lambda
/// - `output_len`: the length of the hash output in bytes
///
/// Returns `shake256(m||n1||r)`
///
/// # Example
/// ```
/// use blind_signatures_conservative::commitment::shake256_commitment;
/// let m = vec![42;21];
/// let n1 = vec![1;8];
/// let r = vec![0;10];
///
/// let com = shake256_commitment(&m, &n1, &r, 32);
/// ```
pub fn shake256_commitment(
    m: &CommitmentMessageType,
    n1: &CommitmentPseudonymType,
    r: &CommitmentRandomnessType,
    output_len: usize,
) -> CommitmentType {
    let mut output = vec![0; output_len];

    let mut input = Vec::with_capacity(m.len() + n1.len() + r.len());
    input.extend(m);
    input.extend(n1);
    input.extend(r);

    unsafe { shake256(output.as_mut_ptr(), output_len, input.as_ptr(), input.len()) };

    output
}

#[cfg(test)]
mod tests {
    use super::shake256_commitment;

    #[test]
    fn commitment_is_deterministic_and_binds_pseudonym() {
        let m = vec![42; 21];
        let n1 = vec![1; 8];
        let other_n1 = vec![2; 8];
        let r = vec![0; 10];

        let com = shake256_commitment(&m, &n1, &r, 32);

        assert_eq!(com.len(), 32);
        assert_eq!(com, shake256_commitment(&m, &n1, &r, 32));
        assert_ne!(com, shake256_commitment(&m, &other_n1, &r, 32));
    }
}
