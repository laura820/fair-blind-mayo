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
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L1 = VOLEMAYO_R_BITS_L1 + VOLEMAYO_S_BITS_L1;        // r + s bits
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
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L3 = VOLEMAYO_R_BITS_L3 + VOLEMAYO_S_BITS_L3;        // r + s bits
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
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS_L5 = VOLEMAYO_R_BITS_L5 + VOLEMAYO_S_BITS_L5;        // r + s bits
constexpr std::size_t VOLEMAYO_COMMIT_MU_SIZE_BYTES_L5 = 32;
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_64 = {8, 0, 2, 8};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_78 = {8, 1, 1, 0};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_108 = {8, 0, 1, 7};
constexpr std::array<uint8_t, 4> VOLEMAYO_F_TAIL_142 = {4, 0, 8, 1};

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
constexpr std::size_t VOLEMAYO_V = (VOLEMAYO_N<S> - VOLEMAYO_O<S>);

template <secpar S>
constexpr std::size_t VOLEMAYO_K = secpar_to_bytes(S) == 16 ? VOLEMAYO_K_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_K_L3 : VOLEMAYO_K_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_N_MINUS_O = VOLEMAYO_N<S> - VOLEMAYO_O<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_Q = secpar_to_bytes(S) == 16 ? VOLEMAYO_Q_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_Q_L3 : VOLEMAYO_Q_L5);

                                        
// elem size in bits params
template <secpar S>
constexpr std::size_t VOLEMAYO_R_BITS = secpar_to_bytes(S) == 16 ? VOLEMAYO_R_BITS_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_R_BITS_L3 : VOLEMAYO_R_BITS_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_S_BITS = secpar_to_bytes(S) == 16 ? VOLEMAYO_S_BITS_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_S_BITS_L3 : VOLEMAYO_S_BITS_L5);

// Elem size in bytes params

template <secpar S>
constexpr std::size_t VOLEMAYO_R_BYTES = (VOLEMAYO_R_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_S_BYTES = (VOLEMAYO_S_BITS<S> + 7) / 8;
template <secpar S>
constexpr std::size_t VOLEMAYO_SALT_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_SALT_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_SALT_BYTES_L3 : VOLEMAYO_SALT_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_DIGEST_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_DIGEST_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_DIGEST_BYTES_L3 : VOLEMAYO_DIGEST_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_PK_SEED_BYTES = secpar_to_bytes(S) == 16 ? VOLEMAYO_PK_SEED_BYTES_L1 : 
                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_PK_SEED_BYTES_L3 : VOLEMAYO_PK_SEED_BYTES_L5);
template <secpar S>
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BITS = (secpar_to_bytes(S) == 16 ? VOLEMAYO_WITNESS_SIZE_BITS_L1 : 
                                                        (secpar_to_bytes(S) == 24 ? VOLEMAYO_WITNESS_SIZE_BITS_L3 : VOLEMAYO_WITNESS_SIZE_BITS_L5));
template <secpar S>
constexpr std::size_t VOLEMAYO_WITNESS_SIZE_BYTES = (VOLEMAYO_WITNESS_SIZE_BITS<S> + 7)/8;

template <secpar S>
constexpr std::size_t VOLEMAYO_SECRET_KEY_SIZE_BYTES = 0;

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
constexpr std::size_t VOLEMAYO_PROVE_1_H_SIZE_BYTES = (VOLEMAYO_M<S>) / VOLEMAYO_FIELD_IN_UINT8;
template <secpar S>
constexpr std::size_t VOLEMAYO_PROVE_1_H_ELEM_SIZE = VOLEMAYO_M<S>;
template <secpar S>
constexpr std::size_t VOLEMAYO_E_SIZE_BYTES = (VOLEMAYO_M<S> * VOLEMAYO_M<S>) / VOLEMAYO_FIELD_IN_UINT8;

template <secpar S>
constexpr std::size_t VOLEMAYO_u64s_per_m_vec = (VOLEMAYO_M<S> + 15) / 16;
template <secpar S>
constexpr std::size_t VOLEMAYO_secpar_polys_per_m_vec = (VOLEMAYO_M<S>*4 + secpar_to_bits(S) - 1) / secpar_to_bits(S);
template <secpar S>
constexpr std::size_t VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s = ((VOLEMAYO_N<S>*(VOLEMAYO_N<S> + 1)) / 2 * VOLEMAYO_u64s_per_m_vec<S>);
template <secpar S>
constexpr std::size_t VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES = VOLEMAYO_EXPANDED_PUBLIC_KEY_U64s<S> * sizeof(uint64_t);
template <secpar S>
constexpr std::size_t VOLEMAYO_PUBLIC_SIZE_BYTES = VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<S> + VOLEMAYO_PROVE_1_H_SIZE_BYTES<S>; 


template <secpar S>
constexpr std::array VOLEMAYO_F_TAIL = (secpar_to_bytes(S) == 16? VOLEMAYO_F_TAIL_78: secpar_to_bytes(S) == 24? VOLEMAYO_F_TAIL_108 : VOLEMAYO_F_TAIL_142);

template<secpar S>
constexpr std::size_t VOLEMAYO_F_TAIL_LEN = 4;

template <secpar S>
constexpr std::size_t VOLEMAYO_SECRET_SIZE_BYTES = VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLEMAYO_WITNESS_SIZE_BYTES<S> + VOLEMAYO_SECRET_KEY_SIZE_BYTES<S>;    



namespace
{
constexpr unsigned int owf_algo_ecb = 0;
constexpr unsigned int owf_algo_em = 2;
constexpr unsigned int owf_algo_mayo = 4;
constexpr unsigned int owf_algo_shift = 8;
constexpr unsigned int owf_flag_zero_sboxes = 0b0001;
constexpr unsigned int owf_flag_norm_proof = 0b0010;
constexpr unsigned int owf_flag_shrunk_keyspace = 0b0100;
constexpr unsigned int owf_flag_ctr_input = 0b1000;
} // namespace

// Enum of the supported one-way functions
enum class owf : unsigned int
{
    aes_ecb = owf_algo_ecb << owf_algo_shift,
    aes_em = owf_algo_em << owf_algo_shift,
    mayo = owf_algo_mayo << owf_algo_shift,

    aes_ecb_with_zero_sboxes = aes_ecb | owf_flag_zero_sboxes,
    aes_em_with_zero_sboxes = aes_em | owf_flag_zero_sboxes,
    mayo_with_zero_sboxes = mayo | owf_flag_zero_sboxes,

    aes_ecb_with_zero_sboxes_and_norm_proof = aes_ecb_with_zero_sboxes | owf_flag_norm_proof,
    aes_em_with_zero_sboxes_and_norm_proof = aes_em_with_zero_sboxes | owf_flag_norm_proof,
    mayo_with_zero_sboxes_and_norm_proof = mayo_with_zero_sboxes | owf_flag_norm_proof,

    v1 = aes_ecb,
    v1_em = aes_em,
    v1_mayo = mayo,
    v2 = aes_ecb | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace |
         owf_flag_ctr_input,
    v2_em = aes_em | owf_flag_zero_sboxes | owf_flag_norm_proof | owf_flag_shrunk_keyspace,
    v2_mayo = mayo,
};

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
using faest_128_s = parameter_set<secpar::s128, 11, owf::aes_ecb, prg::aes_ctr>;
using faest_128_f = parameter_set<secpar::s128, 16, owf::aes_ecb, prg::aes_ctr>;
using faest_192_s = parameter_set<secpar::s192, 16, owf::aes_ecb, prg::aes_ctr>;
using faest_192_f = parameter_set<secpar::s192, 24, owf::aes_ecb, prg::aes_ctr>;
using faest_256_s = parameter_set<secpar::s256, 22, owf::aes_ecb, prg::aes_ctr>;
using faest_256_f = parameter_set<secpar::s256, 32, owf::aes_ecb, prg::aes_ctr>;

using faest_em_128_s = parameter_set<secpar::s128, 11, owf::aes_em, prg::aes_ctr>;
using faest_em_128_f = parameter_set<secpar::s128, 16, owf::aes_em, prg::aes_ctr>;
using faest_em_192_s = parameter_set<secpar::s192, 16, owf::aes_em, prg::aes_ctr>;
using faest_em_192_f = parameter_set<secpar::s192, 24, owf::aes_em, prg::aes_ctr>;
using faest_em_256_s = parameter_set<secpar::s256, 22, owf::aes_em, prg::aes_ctr>;
using faest_em_256_f = parameter_set<secpar::s256, 32, owf::aes_em, prg::aes_ctr>;

using mayo_128_s = parameter_set<secpar::s128, 9, owf::mayo, prg::aes_ctr, prg::aes_ctr>;
using mayo_128_f = parameter_set<secpar::s128, 16, owf::mayo, prg::aes_ctr, prg::aes_ctr>;
using mayo_192_s = parameter_set<secpar::s192, 14, owf::mayo, prg::aes_ctr, prg::aes_ctr>;
using mayo_192_f = parameter_set<secpar::s192, 24, owf::mayo, prg::aes_ctr, prg::aes_ctr>;
using mayo_256_s = parameter_set<secpar::s256, 19, owf::mayo, prg::aes_ctr, prg::aes_ctr>;
using mayo_256_f = parameter_set<secpar::s256, 32, owf::mayo, prg::aes_ctr, prg::aes_ctr>;

} // namespace v1

// Macro listing all instances, useful to instantiate tests with all parameter sets
#define ALL_FAEST_V1_INSTANCES                                                                     \
    v1::faest_128_s, v1::faest_128_f, v1::faest_192_s, v1::faest_192_f, v1::faest_256_s,           \
        v1::faest_256_f, v1::faest_em_128_s, v1::faest_em_128_f, v1::faest_em_192_s,               \
        v1::faest_em_192_f, v1::faest_em_256_s, v1::faest_em_256_f, v1::mayo_128_s,              \
        v1::mayo_128_f, v1::mayo_192_s, v1::mayo_192_f, v1::mayo_256_s, v1::mayo_256_f 

// The FAEST v2 instances (XXX: not finalized yet)
namespace v2
{
    // Also seemed like a decent tradeoff:
    // using faest_128_s = parameter_set<secpar::s128, 10, owf::v2, prg::aes_ctr, prg::aes_ctr, leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 105}>;

using faest_128_s = parameter_set<secpar::s128, 11, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 7, {bavc::one_tree, 102}>;
using faest_128_f = parameter_set<secpar::s128, 16, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 110}>;
using faest_192_s = parameter_set<secpar::s192, 16, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 162}>;
using faest_192_f = parameter_set<secpar::s192, 24, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 163}>;
using faest_256_s = parameter_set<secpar::s256, 22, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 6, {bavc::one_tree, 245}>;
using faest_256_f = parameter_set<secpar::s256, 32, owf::v2, prg::aes_ctr, prg::aes_ctr,
                                  leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 246}>;

using faest_em_128_s = parameter_set<secpar::s128, 11, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 7, {bavc::one_tree, 103}>;
using faest_em_128_f = parameter_set<secpar::s128, 16, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 8, {bavc::one_tree, 112}>;
using faest_em_192_s = parameter_set<secpar::s192, 16, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 8, {bavc::one_tree, 162}>;
using faest_em_192_f = parameter_set<secpar::s192, 24, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 8, {bavc::one_tree, 176}>;
using faest_em_256_s = parameter_set<secpar::s256, 22, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 6, {bavc::one_tree, 218}>;
using faest_em_256_f = parameter_set<secpar::s256, 32, owf::v2_em, prg::aes_ctr, prg::aes_ctr,
                                     leaf_hash::aes_ctr, 8, {bavc::one_tree, 234}>;


using mayo_128_s = parameter_set<secpar::s128, 11, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 7, {bavc::one_tree, 102}>;
using mayo_128_f = parameter_set<secpar::s128, 16, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 110}>;
using mayo_192_s = parameter_set<secpar::s192, 16, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 12, {bavc::one_tree, 162}>;
using mayo_192_f = parameter_set<secpar::s192, 24, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 163}>;
using mayo_256_s = parameter_set<secpar::s256, 22, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 6, {bavc::one_tree, 245}>;
using mayo_256_f = parameter_set<secpar::s256, 32, owf::v2_mayo, prg::aes_ctr, prg::aes_ctr,
                                    leaf_hash::aes_ctr_stat_bind, 8, {bavc::one_tree, 246}>;
                 
} // namespace v2

// Macro listing all instances, useful to instantiate tests with all parameter sets
#define ALL_FAEST_V2_INSTANCES                                                                     \
    v2::faest_128_s, v2::faest_128_f, v2::faest_192_s, v2::faest_192_f, v2::faest_256_s,           \
        v2::faest_256_f, v2::faest_em_128_s, v2::faest_em_128_f, v2::faest_em_192_s,               \
        v2::faest_em_192_f, v2::faest_em_256_s, v2::faest_em_256_f, v2::mayo_128_s,                 \
        v2::mayo_128_f, v2::mayo_192_s, v2::mayo_192_f, v2::mayo_256_s, v2::mayo_256_f

#define ALL_FAEST_INSTANCES ALL_FAEST_V1_INSTANCES, ALL_FAEST_V2_INSTANCES

} // namespace faest

#endif
