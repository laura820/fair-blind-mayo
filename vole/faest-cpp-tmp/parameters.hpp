#define WITH_KECCAK
#define PLUS_MAYO
#ifndef PARAMETERS_HPP
#define PARAMETERS_HPP

#include <cstdint>
#include <type_traits>
#include <utility>
#include <array>

#define DEBUG_MODE 1

namespace faest
{

// Enum representing the security parameter
enum class secpar : std::size_t
{
    s128 = 128,
    s192 = 192,
    s256 = 256,
};

// Convert the security parameter to the corresponding number of bits
constexpr std::size_t secpar_to_bits(secpar s) { return std::to_underlying(s); }
// Convert the security parameter to the corresponding number of bytes
constexpr std::size_t secpar_to_bytes(secpar s) { return secpar_to_bits(s) / 8; }


// ############# MAYO PARAMTERS ##############
// General params
constexpr std::size_t VOLEMAYO_BIN_FIELD_SIZE = 4;
constexpr std::size_t VOLEMAYO_FIELD_IN_UINT8 = 8/VOLEMAYO_BIN_FIELD_SIZE;
constexpr std::size_t VOLEMAYO_MOD = (1 << VOLEMAYO_BIN_FIELD_SIZE) | 2 | 1; // modulus=x^4 + x + 1 00010011
// Sec Lvl specific params
constexpr std::size_t VOLEMAYO_N_L1 = 86;
constexpr std::size_t VOLEMAYO_M_L1 = 78;
constexpr std::size_t VOLEMAYO_O_L1 = 8;
constexpr std::size_t VOLEMAYO_K_L1 = 10;
constexpr std::size_t VOLEMAYO_Q_L1 = 16;
constexpr std::size_t VOLEMAYO_SALT_BYTES_L1 = 24;
constexpr std::size_t VOLEMAYO_DIGEST_BYTES_L1 = 32;
constexpr std::size_t VOLEMAYO_PK_SEED_BYTES_L1 = 16;       // seed expands to the full pk
constexpr std::size_t VOLEMAYO_R_BITS_L1 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_M_L1;    // witness r bits
constexpr std::size_t VOLEMAYO_S_BITS_L1 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_K_L1 * VOLEMAYO_N_L1;  // witness s bits
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L1 = VOLEMAYO_S_BITS_L1;        // r + s bits
constexpr std::size_t VOLEMAYO_COMMIT_MU_SIZE_BYTES_L1 = 16;

constexpr std::size_t VOLEMAYO_N_L3 = 118;       // NOTE: In the spec, it is 99!, we set to 100 such that witness b is divisible by 8
                                                // TODO: check for security implications!, most likely there is none : )
constexpr std::size_t VOLEMAYO_M_L3 = 108;
constexpr std::size_t VOLEMAYO_O_L3 = 10;
constexpr std::size_t VOLEMAYO_K_L3 = 11;
constexpr std::size_t VOLEMAYO_Q_L3 = 16;
constexpr std::size_t VOLEMAYO_SALT_BYTES_L3 = 32;
constexpr std::size_t VOLEMAYO_DIGEST_BYTES_L3 = 48;
constexpr std::size_t VOLEMAYO_PK_SEED_BYTES_L3 = 16;       // seed expands to the full pk
constexpr std::size_t VOLEMAYO_R_BITS_L3 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_M_L3;    // witness r bits
constexpr std::size_t VOLEMAYO_S_BITS_L3 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_K_L3 * VOLEMAYO_N_L3;  // witness s bits
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L3 = VOLEMAYO_S_BITS_L3;        // r + s bits
constexpr std::size_t VOLEMAYO_COMMIT_MU_SIZE_BYTES_L3 = 24;

constexpr std::size_t VOLEMAYO_N_L5 = 154;
constexpr std::size_t VOLEMAYO_M_L5 = 142;
constexpr std::size_t VOLEMAYO_O_L5 = 12;
constexpr std::size_t VOLEMAYO_K_L5 = 12;
constexpr std::size_t VOLEMAYO_Q_L5 = 16;
constexpr std::size_t VOLEMAYO_SALT_BYTES_L5 = 40;
constexpr std::size_t VOLEMAYO_DIGEST_BYTES_L5 = 64;
constexpr std::size_t VOLEMAYO_PK_SEED_BYTES_L5 = 16;       // seed expands to the full pk
constexpr std::size_t VOLEMAYO_R_BITS_L5 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_M_L5;    // witness r bits
constexpr std::size_t VOLEMAYO_S_BITS_L5 = VOLEMAYO_BIN_FIELD_SIZE * VOLEMAYO_K_L5 * VOLEMAYO_N_L5;  // witness s bits
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L5 = VOLEMAYO_S_BITS_L5;        // r + s bits
constexpr std::size_t VOLEMAYO_COMMIT_MU_SIZE_BYTES_L5 = 32;
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_64 = {8, 0, 2, 8};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_78 = {8, 1, 1, 0};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_108 = {8, 0, 1, 7};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_142 = {4, 0, 8, 1};
template <secpar S>
constexpr std::array VOLEMAYO_F_TAIL = (secpar_to_bytes(S) == 16? VOLEMAYO_F_TAIL_78: secpar_to_bytes(S) == 24? VOLEMAYO_F_TAIL_108 : VOLEMAYO_F_TAIL_142);

// Elem size params
template <secpar S>
constexpr std::size_t VOLEMAYO_N = secpar_to_bytes(S) == 16 ? VOLEMAYO_N_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_N_L3 : VOLEMAYO_N_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_M = secpar_to_bytes(S) == 16 ? VOLEMAYO_M_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_M_L3 : VOLEMAYO_M_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_O = secpar_to_bytes(S) == 16 ? VOLEMAYO_O_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_O_L3 : VOLEMAYO_O_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_K = secpar_to_bytes(S) == 16 ? VOLEMAYO_K_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_K_L3 : VOLEMAYO_K_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_N_MINUS_O = VOLEMAYO_N<S> - VOLEMAYO_O<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_V = VOLEMAYO_N_MINUS_O<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_Q = secpar_to_bytes(S) == 16 ? VOLEMAYO_Q_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_Q_L3 : VOLEMAYO_Q_L5);                 
// elem size in bits params
template <secpar S>
constexpr std::size_t VOLEMAYO_S_BITS = secpar_to_bytes(S) == 16 ? VOLEMAYO_S_BITS_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_S_BITS_L3 : VOLEMAYO_S_BITS_L5);
// Elem size in bytes params
template <secpar S>
constexpr std::size_t VOLEMAYO_S_BYTES = (VOLEMAYO_S_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_SALT_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_SALT_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_SALT_BYTES_L3 : VOLEMAYO_SALT_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_SALT_BITS = VOLEMAYO_SALT_BYTES<S> * 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_DIGEST_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_DIGEST_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_DIGEST_BYTES_L3 : VOLEMAYO_DIGEST_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_DIGEST_BITS = VOLEMAYO_DIGEST_BYTES<S> * 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_PK_SEED_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_PK_SEED_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_PK_SEED_BYTES_L3 : VOLEMAYO_PK_SEED_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS = (secpar_to_bytes(S) == 16 ? VOLEMAYO_WITNESS_SIZE_BITS_L1 : 
                                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_WITNESS_SIZE_BITS_L3 : VOLEMAYO_WITNESS_SIZE_BITS_L5));
template <secpar S>
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BYTES = (VOLEMAYO_WITNESS_SIZE_BITS<S> + 7)/8;

template <secpar S>
constexpr std::size_t VOLEMAYO_SECRET_KEY_SIZE_BYTES = VOLEMAYO_WITNESS_SIZE_BYTES<S>;

template <secpar S>
constexpr std::size_t VOLEMAYO_COMMIT_MU_SIZE_BYTES = (secpar_to_bytes(S) == 16 ? VOLEMAYO_COMMIT_MU_SIZE_BYTES_L1 : 
                                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_COMMIT_MU_SIZE_BYTES_L3 : VOLEMAYO_COMMIT_MU_SIZE_BYTES_L5));
// template <secpar S>
template <secpar S>
constexpr std::size_t VOLEMAYO_P1_SIZE_BYTES = (VOLEMAYO_M<S> * (VOLEMAYO_N<S> - VOLEMAYO_O<S>) * (VOLEMAYO_N<S> - VOLEMAYO_O<S>))/VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t VOLEMAYO_P2_SIZE_BYTES = (VOLEMAYO_M<S> * (VOLEMAYO_N<S> - VOLEMAYO_O<S>) * (VOLEMAYO_O<S>))/VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t VOLEMAYO_P3_SIZE_BYTES = (VOLEMAYO_M<S> * (VOLEMAYO_O<S> * VOLEMAYO_O<S>))/VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t VOLEMAYO_P1_SUBMATRIX_ELEM_SIZE = (VOLEMAYO_N<S> - VOLEMAYO_O<S>) * (VOLEMAYO_N<S> - VOLEMAYO_O<S>);
template <secpar S>
constexpr std::size_t VOLEMAYO_P1_ELEM_SIZE = VOLEMAYO_M<S> * VOLEMAYO_P1_SUBMATRIX_ELEM_SIZE<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_P2_SUBMATRIX_ELEM_SIZE = (VOLEMAYO_N<S> - VOLEMAYO_O<S>) * (VOLEMAYO_O<S>);
template <secpar S>
constexpr std::size_t VOLEMAYO_P2_ELEM_SIZE = VOLEMAYO_M<S> * VOLEMAYO_P2_SUBMATRIX_ELEM_SIZE<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_P3_SUBMATRIX_ELEM_SIZE = (VOLEMAYO_O<S> * VOLEMAYO_O<S>);
template <secpar S>
constexpr std::size_t VOLEMAYO_P3_ELEM_SIZE = VOLEMAYO_M<S> * VOLEMAYO_P3_SUBMATRIX_ELEM_SIZE<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_T_SIZE_BYTES = (VOLEMAYO_M<S>) / VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t VOLEMAYO_T_ELEM_SIZE = VOLEMAYO_M<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_E_SIZE_BYTES = (VOLEMAYO_M<S> * VOLEMAYO_M<S>) / VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t HASHED_MSG_SIZE_BITS = secpar_to_bits(S);
template <secpar S>
constexpr std::size_t CPK_SIZE_BITS = secpar_to_bits(S);
template <secpar S>
constexpr std::size_t RAND_SIZE_BITS = secpar_to_bits(S);
template <secpar S>
constexpr std::size_t RAND_SIZE_BYTES = (RAND_SIZE_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t PSEUDONYM_SIZE_BITS = secpar_to_bits(S);
template <secpar S>
constexpr std::size_t PSEUDONYM_SIZE_BYTES = (PSEUDONYM_SIZE_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t OPENING_SIZE_BITS = PSEUDONYM_SIZE_BITS<S> + RAND_SIZE_BITS<S>;
template <secpar S>
constexpr std::size_t OPENING_SIZE_BYTES = PSEUDONYM_SIZE_BYTES<S> + RAND_SIZE_BYTES<S>;
template <secpar S>
constexpr std::size_t HASHED_MSG_SIZE_BYTES = (HASHED_MSG_SIZE_BITS<S> + 7) / 8;
// template <secpar S>
// constexpr std::size_t CPK_SIZE_BYTES = (CPK_SIZE_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_u64s_per_m_vec = (VOLEMAYO_M<S> + 15) / 16;
template <secpar S>
constexpr std::size_t VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s = ((VOLEMAYO_N<S>*(VOLEMAYO_N<S> + 1)) / 2 * VOLEMAYO_u64s_per_m_vec<S>);
template <secpar S>
constexpr std::size_t VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES = VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<S> * sizeof(uint64_t);
template <secpar S>
// constexpr std::size_t VOLEMAYO_PUBLIC_SIZE_BYTES =  VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S> + CPK_SIZE_BYTES<S> + HASHED_MSG_SIZE_BYTES<S>;
constexpr std::size_t VOLEMAYO_PUBLIC_SIZE_BYTES =  VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S> + HASHED_MSG_SIZE_BYTES<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_SECRET_SIZE_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLEMAYO_S_BYTES<S>;


#if defined WITH_KECCAK
// ############# KECCAK PARAMTERS ##############
constexpr std::size_t VOLEKECCAK_W = 64;
constexpr uint8_t VOLEKECCAK_PADDING_D = 31;
constexpr uint8_t VOLEKECCAK_PADDING_0X80 = 128;
constexpr std::size_t VOLEKECCAK_B = 1600;
constexpr std::size_t VOLEKECCAK_NUM_ROUNDS = 24;
constexpr std::size_t VOLEKECCAK_RATE = 1088;
constexpr std::size_t VOLEKECCAK_RATE_BYTES = (VOLEKECCAK_RATE+7)/8;
constexpr std::size_t VOLEKECCAK_CAPACITY = VOLEKECCAK_B - VOLEKECCAK_RATE; // 512 bits
// constexpr std::size_t VOLEKECCAK_PK_OUTPUT_BYTES = (VOLEKECCAK_RATE + 7)/8;
constexpr std::size_t VOLEKECCAK_PK_OUTPUT_BYTES = 0; // output of keccak is still private for the mayo part
constexpr std::size_t VOLEKECCAK_PUBLIC_SIZE_BYTES = VOLEKECCAK_PK_OUTPUT_BYTES;  // pk output

#if defined KECCAK_DEG_16
// 4 rounds forward, 2 rounds backward, contains intermediate witness and the output
template <secpar S>
constexpr std::size_t VOLEKECCAK_WITNESS_SIZE_BITS = OPENING_SIZE_BITS<S> + (VOLEKECCAK_B*((VOLEKECCAK_NUM_ROUNDS/6)-1) + VOLEKECCAK_B)
                                                + VOLEKECCAK_B + (VOLEKECCAK_B*((VOLEKECCAK_NUM_ROUNDS/6)-1) + VOLEKECCAK_B); 
                                                // ^^^^^^^
                                                // This one is the M_digest and the signature salt  
#else
template <secpar S>
constexpr std::size_t VOLEKECCAK_WITNESS_SIZE_BITS = OPENING_SIZE_BITS<S> + (VOLEKECCAK_B*(VOLEKECCAK_NUM_ROUNDS-1) + VOLEKECCAK_B)
                                                + VOLEKECCAK_B + (VOLEKECCAK_B*(VOLEKECCAK_NUM_ROUNDS-1) + VOLEKECCAK_B);  // the output is never revealed
                                                // ^^^^^^^
                                                // This one is the M_digest and the signature salt 
#endif
constexpr std::size_t VOLEKECCAK_B_BYTES = (VOLEKECCAK_B + 7)/8;

template <secpar S>
constexpr std::size_t VOLEKECCAK_WITNESS_SIZE_BYTES = (VOLEKECCAK_WITNESS_SIZE_BITS<S> + 7)/8;

template <secpar S>
constexpr std::size_t VOLEKECCAK_SECRET_SIZE_BYTES = VOLEKECCAK_PUBLIC_SIZE_BYTES + VOLEKECCAK_WITNESS_SIZE_BYTES<S>; 
// SHA3-256 L1
constexpr std::size_t VOLEKECCAK_OUTPUT_LEN_BITS_L1 = 256;  // Digest_bytes = 32 bytes
constexpr std::size_t VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L1 = 16;
// SHA3-384 L3
constexpr std::size_t VOLEKECCAK_OUTPUT_LEN_BITS_L3 = 384;  // Digest_bytes = 48 bytes
constexpr std::size_t VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L3 = 24;
// SHA3-512 L5
constexpr std::size_t VOLEKECCAK_OUTPUT_LEN_BITS_L5 = 512;  // Digest_bytes = 64 bytes
constexpr std::size_t VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L5 = 32;
template <secpar S>
constexpr std::size_t VOLEKECCAK_OUTPUT_LEN_BITS = (secpar_to_bytes(S) == 16 ? VOLEKECCAK_OUTPUT_LEN_BITS_L1 : 
                                                    (secpar_to_bytes(S) == 24 ? VOLEKECCAK_OUTPUT_LEN_BITS_L3 : VOLEKECCAK_OUTPUT_LEN_BITS_L5));
// NOTE: This is the output len that is actually used further in the protocol, rest from the rate we just ignore, but used in the proof
template <secpar S>
constexpr std::size_t VOLEKECCAK_OUTPUT_LEN_BYTES = (VOLEKECCAK_OUTPUT_LEN_BITS<S> + 7)/8;
template <secpar S>
constexpr std::size_t VOLEKECCAK_COMMIT_MU_SIZE_BYTES = (secpar_to_bytes(S) == 16 ? VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L1 : 
                                                        (secpar_to_bytes(S) == 24 ? VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L3 : VOLEKECCAK_COMMIT_MU_SIZE_BYTES_L5));

template <secpar S>                                                
// constexpr std::size_t VOLEKECCAK_COMMITMENT_INPUT_BYTES = CPK_SIZE_BYTES<S> + HASHED_MSG_SIZE_BYTES<S> + OPENING_SIZE_BYTES<S>;
constexpr std::size_t VOLEKECCAK_COMMITMENT_INPUT_BYTES = HASHED_MSG_SIZE_BYTES<S> + OPENING_SIZE_BYTES<S>;
template <secpar S>
constexpr std::size_t VOLEKECCAK_MAYO_HASH_INPUT_BYTES =  VOLEMAYO_DIGEST_BYTES<S> + VOLEMAYO_SALT_BYTES<S>;
#endif

#if defined WITH_RAINHASH
// ############# RAIN PARAMTERS ##############
constexpr std::size_t VOLERAINHASH_RC_SIZE_BITS = 64*7 * 8;
constexpr std::size_t VOLERAINHASH_MAT_SIZE_BITS = 64*512*7 * 8; 
constexpr std::size_t VOLERAINHASH_RC_SIZE_BYTES = VOLERAINHASH_RC_SIZE_BITS / 8;
constexpr std::size_t VOLERAINHASH_MAT_SIZE_BYTES = VOLERAINHASH_MAT_SIZE_BITS / 8; 

constexpr std::size_t VOLERAINHASH_SBOX_SIZE = 512;
constexpr std::size_t VOLERAINHASH_B = 512;
constexpr std::size_t VOLERAINHASH_B_BYTES = (VOLERAINHASH_B + 7)/8;
constexpr std::size_t VOLERAINHASH_NUM_ROUNDS = 7;
constexpr std::size_t VOLERAINHASH_RATE = 512;
constexpr std::size_t VOLERAINHASH_RATE_BYTES = (VOLERAINHASH_RATE+7)/8;
constexpr std::size_t VOLERAINHASH_CAPACITY = VOLERAINHASH_B - VOLERAINHASH_RATE; // 256 bits
constexpr std::size_t VOLERAINHASH_PK_OUTPUT_BYTES = 0; // output of rainhash is still private for the mayo part
constexpr std::size_t VOLERAINHASH_PUBLIC_SIZE_BYTES = VOLERAINHASH_PK_OUTPUT_BYTES + VOLERAINHASH_RC_SIZE_BYTES + VOLERAINHASH_MAT_SIZE_BYTES;  // pk output

template <secpar S>  
//                                                       input                  witness                             output
constexpr std::size_t VOLERAINHASH_WITNESS_SIZE_BITS = VOLERAINHASH_B + VOLERAINHASH_B*(VOLERAINHASH_NUM_ROUNDS) + VOLERAINHASH_B
//                      input                   witness                             output
                    + VOLERAINHASH_B + VOLERAINHASH_B*(VOLERAINHASH_NUM_ROUNDS) + VOLERAINHASH_B;

template <secpar S>  
constexpr std::size_t VOLERAINHASH_WITNESS_SIZE_BYTES = (VOLERAINHASH_WITNESS_SIZE_BITS<S> + 7)/8;

template <secpar S>  
constexpr std::size_t VOLERAINHASH_SECRET_SIZE_BYTES = VOLERAINHASH_PUBLIC_SIZE_BYTES + VOLERAINHASH_WITNESS_SIZE_BYTES<S>;

constexpr std::size_t VOLERAINHASH_ONE_ROUND_RC_SIZE_BYTES = 64;
constexpr std::size_t VOLERAINHASH_ONE_ROUND_MAT_SIZE_BYTES = 64*512;

// Rain L1
constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BITS_L1 = 512;  // Digest_bytes = 32 bytes
constexpr std::size_t VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L1 = 16;

template <secpar S>                                                
// constexpr std::size_t VOLERAINHASH_COMMITMENT_INPUT_BYTES = CPK_SIZE_BYTES<S> + HASHED_MSG_SIZE_BYTES<S> + RAND_SIZE_BYTES<S>;
constexpr std::size_t VOLERAINHASH_COMMITMENT_INPUT_BYTES = HASHED_MSG_SIZE_BYTES<S> + RAND_SIZE_BYTES<S>;
template <secpar S>
constexpr std::size_t VOLERAINHASH_MAYO_HASH_INPUT_BYTES =  VOLEMAYO_DIGEST_BYTES<S> + VOLEMAYO_SALT_BYTES<S>;

// // Rain L3
// constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BITS_L3 = 384;  // Digest_bytes = 48 bytes
// constexpr std::size_t VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L3 = 24;
// // Rain L5
// constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BITS_L5 = 512;  // Digest_bytes = 64 bytes
// constexpr std::size_t VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L5 = 32;

// template <secpar S>
// constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BITS = (secpar_to_bytes(S) == 16 ? VOLERAINHASH_OUTPUT_LEN_BITS_L1 : 
//                                                     (secpar_to_bytes(S) == 24 ? VOLERAINHASH_OUTPUT_LEN_BITS_L3 : VOLERAINHASH_OUTPUT_LEN_BITS_L5));
// // NOTE: This is the output len that is actually used further in the protocol, rest from the rate we just ignore, but used in the proof
// template <secpar S>
// constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BYTES = (VOLERAINHASH_OUTPUT_LEN_BITS<S> + 7)/8;
// template <secpar S>
// constexpr std::size_t VOLERAINHASH_COMMIT_MU_SIZE_BYTES = (secpar_to_bytes(S) == 16 ? VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L1 : 
//                                                         (secpar_to_bytes(S) == 24 ? VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L3 : VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L5));

template <secpar S>
constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BITS = VOLERAINHASH_OUTPUT_LEN_BITS_L1;
// NOTE: This is the output len that is actually used further in the protocol, rest from the rate we just ignore, but used in the proof
template <secpar S>
constexpr std::size_t VOLERAINHASH_OUTPUT_LEN_BYTES = (VOLERAINHASH_OUTPUT_LEN_BITS<S> + 7)/8;
template <secpar S>
constexpr std::size_t VOLERAINHASH_COMMIT_MU_SIZE_BYTES = VOLERAINHASH_COMMIT_MU_SIZE_BYTES_L1;
#endif



namespace
{
constexpr unsigned int owf_algo_ecb = 0;
constexpr unsigned int owf_algo_em = 2;
#if defined WITH_KECCAK
constexpr unsigned int owf_algo_keccak_then_mayo = 4;
#endif
#if defined WITH_RAINHASH
constexpr unsigned int owf_algo_rainhash_then_mayo = 4;
#endif
constexpr unsigned int owf_algo_shift = 8;
constexpr unsigned int owf_flag_zero_sboxes = 0b0001;
constexpr unsigned int owf_flag_norm_proof = 0b0010;
constexpr unsigned int owf_flag_shrunk_keyspace = 0b0100;
constexpr unsigned int owf_flag_ctr_input = 0b1000;
} // namespace

// Enum of the supported one-way functions
enum class owf : unsigned int
{
    #if defined WITH_KECCAK
    aes_ecb = owf_algo_ecb << owf_algo_shift,
    aes_em = owf_algo_em << owf_algo_shift,
    keccak_then_mayo = owf_algo_keccak_then_mayo << owf_algo_shift,

    aes_ecb_with_zero_sboxes = aes_ecb | owf_flag_zero_sboxes,
    aes_em_with_zero_sboxes = aes_em | owf_flag_zero_sboxes,
    keccak_then_mayo_with_zero_sboxes = keccak_then_mayo | owf_flag_zero_sboxes,

    aes_ecb_with_zero_sboxes_and_norm_proof = aes_ecb_with_zero_sboxes | owf_flag_norm_proof,
    aes_em_with_zero_sboxes_and_norm_proof = aes_em_with_zero_sboxes | owf_flag_norm_proof,
    keccak_then_mayo_with_zero_sboxes_and_norm_proof = keccak_then_mayo_with_zero_sboxes | owf_flag_norm_proof,

    v1 = aes_ecb,
    v1_em = aes_em,
    v1_keccak_then_mayo = keccak_then_mayo,
    v2 = aes_ecb | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace |
         owf_flag_ctr_input,
    v2_em = aes_em | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace,
    v2_keccak_then_mayo = keccak_then_mayo,
    #endif

    #if defined WITH_RAINHASH
    aes_ecb = owf_algo_ecb << owf_algo_shift,
    aes_em = owf_algo_em << owf_algo_shift,
    rainhash_then_mayo = owf_algo_rainhash_then_mayo << owf_algo_shift,

    aes_ecb_with_zero_sboxes = aes_ecb | owf_flag_zero_sboxes,
    aes_em_with_zero_sboxes = aes_em | owf_flag_zero_sboxes,
    rainhash_then_mayo_with_zero_sboxes = rainhash_then_mayo | owf_flag_zero_sboxes,

    aes_ecb_with_zero_sboxes_and_norm_proof = aes_ecb_with_zero_sboxes | owf_flag_norm_proof,
    aes_em_with_zero_sboxes_and_norm_proof = aes_em_with_zero_sboxes | owf_flag_norm_proof,
    rainhash_then_mayo_with_zero_sboxes_and_norm_proof = rainhash_then_mayo_with_zero_sboxes | owf_flag_norm_proof,

    v1 = aes_ecb,
    v1_em = aes_em,
    v1_rainhash_then_mayo = rainhash_then_mayo,
    v2 = aes_ecb | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace |
         owf_flag_ctr_input,
    v2_em = aes_em | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace,
    v2_rainhash_then_mayo = rainhash_then_mayo,
    #endif
};

constexpr bool is_owf_with_aes_ecb(owf o)
{
    return (std::to_underlying(o) >> owf_algo_shift) == owf_algo_ecb;
}

constexpr bool is_owf_with_aes_em(owf o)
{
    return (std::to_underlying(o) >> owf_algo_shift) == owf_algo_em;
}

#if defined WITH_KECCAK
constexpr bool is_owf_with_keccak_then_mayo(owf o)
{
    return (std::to_underlying(o) >> owf_algo_shift) == owf_algo_keccak_then_mayo;
}
#endif

#if defined WITH_RAINHASH
constexpr bool is_owf_with_rainhash_then_mayo(owf o)
{
    return (std::to_underlying(o) >> owf_algo_shift) == owf_algo_rainhash_then_mayo;
}
#endif

constexpr bool is_owf_with_zero_sboxes(owf o)
{
    return std::to_underlying(o) & owf_flag_zero_sboxes;
}

constexpr bool is_owf_with_norm_proof(owf o) { return std::to_underlying(o) & owf_flag_norm_proof; }

constexpr bool is_owf_with_shrunk_keyspace(owf o)
{
    return std::to_underlying(o) & owf_flag_shrunk_keyspace;
}

constexpr bool is_owf_with_ctr_input(owf o) { return std::to_underlying(o) & owf_flag_ctr_input; }

// Enum of the supported PRGs
enum class prg
{
    aes_ctr,
    rijndael_fixed_key_ctr,
};

// Enum of the supported leaf hashes
enum class leaf_hash
{
    aes_ctr,
    aes_ctr_stat_bind,
    rijndael_fixed_key_ctr,
    rijndael_fixed_key_ctr_stat_bind,
    shake,
};

// Defined in prgs.hpp
template <secpar S> struct aes_ctr_prg;
template <secpar S> struct rijndael_fixed_key_ctr_prg;

// Defined in vector_com.hpp
template <typename PRG> struct prg_leaf_hash;
template <typename PRG, uint32_t MAX_TWEAKS> struct stat_binding_leaf_hash;
template <secpar S> struct shake_leaf_hash;

// Template to obtain the PRG type corresponding to a prg enum value
template <secpar S, prg PRG> struct prg_type;
template <secpar S, prg PRG> using prg_type_t = prg_type<S, PRG>::type;
template <secpar S> struct prg_type<S, prg::aes_ctr>
{
    using type = aes_ctr_prg<S>;
};
template <secpar S> struct prg_type<S, prg::rijndael_fixed_key_ctr>
{
    using type = rijndael_fixed_key_ctr_prg<S>;
};

// Template to obtain the leaf hash type corresponding to a leaf_hash enum value
template <secpar S, uint32_t MAX_TWEAKS, leaf_hash LH> struct leaf_hash_type;
template <secpar S, uint32_t MAX_TWEAKS, leaf_hash LH>
using leaf_hash_type_t = leaf_hash_type<S, MAX_TWEAKS, LH>::type;
template <secpar S, uint32_t MAX_TWEAKS>
struct leaf_hash_type<S, MAX_TWEAKS, leaf_hash::aes_ctr>
{
    using type = prg_leaf_hash<aes_ctr_prg<S>>;
};
template <secpar S, uint32_t MAX_TWEAKS>
struct leaf_hash_type<S, MAX_TWEAKS, leaf_hash::aes_ctr_stat_bind>
{
    using type = stat_binding_leaf_hash<aes_ctr_prg<S>, MAX_TWEAKS>;
};
template <secpar S, uint32_t MAX_TWEAKS>
struct leaf_hash_type<S, MAX_TWEAKS, leaf_hash::rijndael_fixed_key_ctr>
{
    using type = prg_leaf_hash<rijndael_fixed_key_ctr_prg<S>>;
};
template <secpar S, uint32_t MAX_TWEAKS>
struct leaf_hash_type<S, MAX_TWEAKS, leaf_hash::rijndael_fixed_key_ctr_stat_bind>
{
    using type = stat_binding_leaf_hash<rijndael_fixed_key_ctr_prg<S>, MAX_TWEAKS>;
};
template <secpar S, uint32_t MAX_TWEAKS>
struct leaf_hash_type<S, MAX_TWEAKS, leaf_hash::shake>
{
    using type = shake_leaf_hash<S>;
};

enum class bavc
{
    ggm_forest,
    one_tree,
};

template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT>
struct ggm_forest_bavc;

template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT, std::size_t OPENING_SEEDS_THRESHOLD>
struct one_tree_bavc;

template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT, bavc BAVC, std::size_t BAVC_PARAM>
struct bavc_type;
template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT, bavc BAVC, std::size_t BAVC_PARAM>
using bavc_type_t =
    bavc_type<S, TAU, DELTA_BITS, TREE_PRG, LEAF_HASH, VOLE_WIDTH_SHIFT, BAVC, BAVC_PARAM>::type;
template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT>
struct bavc_type<S, TAU, DELTA_BITS, TREE_PRG, LEAF_HASH, VOLE_WIDTH_SHIFT, bavc::ggm_forest, 0>
{
    using type = ggm_forest_bavc<S, TAU, DELTA_BITS, TREE_PRG, LEAF_HASH, VOLE_WIDTH_SHIFT>;
};
template <secpar S, std::size_t TAU, std::size_t DELTA_BITS, prg TREE_PRG, leaf_hash LEAF_HASH,
          std::size_t VOLE_WIDTH_SHIFT, std::size_t BAVC_PARAM>
struct bavc_type<S, TAU, DELTA_BITS, TREE_PRG, LEAF_HASH, VOLE_WIDTH_SHIFT, bavc::one_tree,
                 BAVC_PARAM>
{
    using type =
        one_tree_bavc<S, TAU, DELTA_BITS, TREE_PRG, LEAF_HASH, VOLE_WIDTH_SHIFT, BAVC_PARAM>;
};

// Defined in constants.hpp
template <secpar S, owf P> struct OWF_CONSTANTS;
template <typename P> struct CONSTANTS;

// Template describing a particular instance of FAEST
//
// The parameters are
// - the security parameter
// - tau = number of bits per witness bit
//       = number of GGM trees
// - the one-way function to prove
// - the PRG used for the VOLEs
// - the PRG used for inner nodes in the GGM trees
// - the PRG used for leaf nodes of the GGM trees
// - number of zero bits in Delta
template <secpar S, std::size_t TAU, owf OWF, prg VOLE_PRG, prg TREE_PRG = prg::aes_ctr,
          leaf_hash LEAF_HASH = leaf_hash::shake, std::size_t ZERO_BITS_IN_DELTA = 0,
          std::pair<bavc, std::size_t> BAVC = {bavc::ggm_forest, 0}>
struct parameter_set
{
    // Values of the template parameters as constants
    constexpr static secpar secpar_v = S;
    constexpr static std::size_t tau_v = TAU;
    constexpr static owf owf_v = OWF;
    constexpr static prg vole_prg_v = VOLE_PRG;
    constexpr static prg tree_prg_v = TREE_PRG;
    constexpr static leaf_hash leaf_hash_v = LEAF_HASH;
    constexpr static std::size_t zero_bits_in_delta_v = ZERO_BITS_IN_DELTA;

    // Shorthands for the security parameter in bits and bytes
    constexpr static std::size_t secpar_bits = secpar_to_bits(S);
    constexpr static std::size_t secpar_bytes = secpar_to_bytes(S);

    // Size of Delta
    constexpr static std::size_t delta_bits_v = secpar_bits - zero_bits_in_delta_v;

    // Access to the implementation constants that depend on the parameters
    using CONSTS = CONSTANTS<
        parameter_set<S, TAU, OWF, VOLE_PRG, TREE_PRG, LEAF_HASH, ZERO_BITS_IN_DELTA, BAVC>>;
    // Access to the one-way function constants that depend on the parameters
    using OWF_CONSTS = OWF_CONSTANTS<S, OWF>;

    // The types of the selected PRGs
    using leaf_hash_t = leaf_hash_type_t<S, TAU, LEAF_HASH>;
    using tree_prg_t = prg_type_t<S, TREE_PRG>;
    using vole_prg_t = prg_type_t<S, VOLE_PRG>;

    // The batched all-but-one vector commitment
    using bavc_t = bavc_type_t<S, TAU, delta_bits_v, TREE_PRG, LEAF_HASH, CONSTS::VOLE_WIDTH_SHIFT,
                               BAVC.first, BAVC.second>;

    constexpr static bool use_grinding =
        (zero_bits_in_delta_v > 0) || !bavc_t::OPEN_ALWAYS_SUCCEEDS;
    constexpr static std::size_t grinding_counter_size = []
    {
        if (use_grinding)
            return 4;
        else
            return 0;
    }();
};


// The FAEST v1 instances
namespace v1
{

#if defined WITH_KECCAK
using keccak_then_mayo_128_s = parameter_set<secpar::s128, 9, owf::v1_keccak_then_mayo, prg::aes_ctr>;
using keccak_then_mayo_128_f = parameter_set<secpar::s128, 16, owf::v1_keccak_then_mayo, prg::aes_ctr>;
using keccak_then_mayo_192_s = parameter_set<secpar::s192, 14, owf::v1_keccak_then_mayo, prg::aes_ctr>;
using keccak_then_mayo_192_f = parameter_set<secpar::s192, 24, owf::v1_keccak_then_mayo, prg::aes_ctr>;
using keccak_then_mayo_256_s = parameter_set<secpar::s256, 20, owf::v1_keccak_then_mayo, prg::aes_ctr>;
using keccak_then_mayo_256_f = parameter_set<secpar::s256, 32, owf::v1_keccak_then_mayo, prg::aes_ctr>;
#endif

#if defined WITH_RAINHASH
using rainhash_then_mayo_128_s = parameter_set<secpar::s128, 9, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
using rainhash_then_mayo_128_f = parameter_set<secpar::s128, 16, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
using rainhash_then_mayo_192_s = parameter_set<secpar::s192, 14, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
using rainhash_then_mayo_192_f = parameter_set<secpar::s192, 24, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
using rainhash_then_mayo_256_s = parameter_set<secpar::s256, 20, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
using rainhash_then_mayo_256_f = parameter_set<secpar::s256, 32, owf::v1_rainhash_then_mayo, prg::aes_ctr>;
#endif
    
} // namespace v1

// The FAEST v2 instances (XXX: not finalized yet)
namespace v2
{
    // Also seemed like a decent tradeoff:
    // using faest_128_s = parameter_set<secpar::s128, 10, owf::v2, prg::aes_ctr, prg::aes_ctr, leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 105}>;

#if defined WITH_KECCAK
using keccak_then_mayo_128_s = parameter_set<secpar::s128, 11, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 7, {bavc::one_tree, 102}>;
using keccak_then_mayo_128_f = parameter_set<secpar::s128, 16, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 110}>;
using keccak_then_mayo_192_s = parameter_set<secpar::s192, 16, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 162}>;
using keccak_then_mayo_192_f = parameter_set<secpar::s192, 24, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 163}>;
using keccak_then_mayo_256_s = parameter_set<secpar::s256, 22, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 6, {bavc::one_tree, 245}>;
using keccak_then_mayo_256_f = parameter_set<secpar::s256, 32, owf::v2_keccak_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 246}>;
#endif

#if defined WITH_RAINHASH
using rainhash_then_mayo_128_s = parameter_set<secpar::s128, 11, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 7, {bavc::one_tree, 102}>;
using rainhash_then_mayo_128_f = parameter_set<secpar::s128, 16, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 110}>;
using rainhash_then_mayo_192_s = parameter_set<secpar::s192, 16, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 162}>;
using rainhash_then_mayo_192_f = parameter_set<secpar::s192, 24, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 163}>;
using rainhash_then_mayo_256_s = parameter_set<secpar::s256, 22, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 6, {bavc::one_tree, 245}>;
using rainhash_then_mayo_256_f = parameter_set<secpar::s256, 32, owf::v2_rainhash_then_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 246}>;
#endif
                 
} // namespace v2

#if defined WITH_KECCAK
// Macro listing all instances, useful to instantiate tests with all parameter sets
#define ALL_FAEST_V2_INSTANCES                                                                     \
    v2::keccak_then_mayo_128_s,                 \
    v2::keccak_then_mayo_128_f, v2::keccak_then_mayo_192_s, v2::keccak_then_mayo_192_f, v2::keccak_then_mayo_256_s, v2::keccak_then_mayo_256_f
#endif

#if defined WITH_RAINHASH
// Macro listing all instances, useful to instantiate tests with all parameter sets
#define ALL_FAEST_V2_INSTANCES                                                                     \
    v2::rainhash_then_mayo_128_s,                 \
    v2::rainhash_then_mayo_128_f, v2::rainhash_then_mayo_192_s, v2::rainhash_then_mayo_192_f, v2::rainhash_then_mayo_256_s, v2::rainhash_then_mayo_256_f
#endif

#define ALL_FAEST_INSTANCES ALL_FAEST_V2_INSTANCES

} // namespace faest

#endif
