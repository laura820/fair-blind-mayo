#ifndef FAEST_INC
#define FAEST_INC

#include "faest.hpp"
#include "faest_keys.inc"

#include "hash.hpp"
#include "owf_proof.hpp"
#include "quicksilver.hpp"
#include "small_vole.hpp"
#include "transpose_secpar.hpp"
#include "util.hpp"
#include "vector_com.inc"
#include "vole_check.hpp"
#include "vole_commit.hpp"
#include <cassert>
#include <cstdalign>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include "test/fips202.h"
}

#if defined WITH_RAINHASH
#include "rainhash_plain/rain_hash.h"
#endif

namespace faest
{

// NOTE: Use these functions to serialize the pk and sk, after Sign2 algorithm
#if defined WITH_KECCAK
template <typename P> inline void serialize_pk(uint8_t* pk, const uint8_t* expanded_pk, const uint8_t* msg_hash) {
#endif
#if defined WITH_RAINHASH
template <typename P> inline void serialize_pk(uint8_t* pk, const uint8_t* expanded_pk, const uint8_t* msg_hash) {
#endif
    #if defined WITH_KECCAK
        memcpy(pk, expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        pk += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;

        memcpy(pk, msg_hash, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
    #endif

    #if defined WITH_RAINHASH
        // the mayo pk
        memcpy(pk, expanded_pk, VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>);
        pk += VOLEMAYO_EXPANDED_PUBLIC_KEY_BYTES<P::secpar_v>;
        memcpy(pk, msg_hash, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        pk += HASHED_MSG_SIZE_BYTES<P::secpar_v>;

        // rainhash pk
        // memcpy(pk, rain_rc, VOLERAINHASH_RC_SIZE_BYTES);
        // pk += VOLERAINHASH_RC_SIZE_BYTES;
        // memcpy(pk, rain_mat, VOLERAINHASH_MAT_SIZE_BYTES);
        // pk += VOLERAINHASH_MAT_SIZE_BYTES;
    #endif
    
}

template <typename P> inline void serialize_sk(uint8_t* sk, const uint8_t* pk, const uint8_t* s, const uint8_t* witness) {
    
    #if defined WITH_KECCAK
    memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
    sk += VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

    memcpy(sk, witness, VOLEKECCAK_WITNESS_SIZE_BYTES<P::secpar_v>);
    sk += VOLEKECCAK_WITNESS_SIZE_BYTES<P::secpar_v>;

    memcpy(sk, s, VOLEMAYO_S_BYTES<P::secpar_v>);
    #endif

    #if defined WITH_RAINHASH
    // copying all the mayo pk stuff to sk
    memcpy(sk, pk, VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>);
    size_t offset = VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
    sk += VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;

    // the rain pk
    memcpy(sk, pk + offset, VOLERAINHASH_PUBLIC_SIZE_BYTES);
    sk += VOLERAINHASH_PUBLIC_SIZE_BYTES;

    // NOTE: First rainhash happens, so store rainhash first after pk
    memcpy(sk, witness, VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>);
    sk += VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>;

    // NOTE: storing the mayo sk
    memcpy(sk, s, VOLEMAYO_S_BYTES<P::secpar_v>);
    #endif

}

template <typename P>
void get_witness(uint8_t* msg_hash, uint8_t* opening, uint8_t* salt, uint8_t* witness) {

    #if defined WITH_KECCAK
        std::array<uint8_t, VOLEKECCAK_COMMITMENT_INPUT_BYTES<P::secpar_v>> commit_input;
        memset((uint8_t*)commit_input.data(), 0x00, VOLEKECCAK_COMMITMENT_INPUT_BYTES<P::secpar_v>);

        size_t offset = 0;        
        // public
        memcpy((uint8_t*)commit_input.data() + offset, msg_hash, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        offset += HASHED_MSG_SIZE_BYTES<P::secpar_v>;
        // witness
        memcpy((uint8_t*)commit_input.data() + offset, opening, OPENING_SIZE_BYTES<P::secpar_v>);
        memcpy(witness, (uint8_t*)commit_input.data() + offset, OPENING_SIZE_BYTES<P::secpar_v>);

        // the modified shake stores all intermediate values of S to witness.
        // the values start in witness + OPENING_SIZE_BYTES<P::secpar_v> and are of length
        // - VOLEKECCAK_B_BYTES*((VOLEKECCAK_NUM_ROUNDS/6))
        // - or VOLEKECCAK_B_BYTES*(VOLEKECCAK_NUM_ROUNDS) for the non degree 16 version
        // the last block contains the last S, and from it the eventual hash value can be read

        #if defined KECCAK_DEG_16
            shake256_w(witness + OPENING_SIZE_BYTES<P::secpar_v>,
                    (uint8_t*)commit_input.data(), VOLEKECCAK_COMMITMENT_INPUT_BYTES<P::secpar_v>);

        #else
            shake256_w(witness + OPENING_SIZE_BYTES<P::secpar_v>,
                    (uint8_t*)commit_input.data(), VOLEKECCAK_COMMITMENT_INPUT_BYTES<P::secpar_v>);
        #endif

        #if defined KECCAK_DEG_16
            size_t input_idx = OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS/6);
            size_t witness_idx = OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS/6 + 1);

            // copying the hash result (of length digest bytes) to a new input block witness
            memcpy(witness + input_idx, witness + (OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES*((VOLEKECCAK_NUM_ROUNDS/6) - 1)), VOLEMAYO_DIGEST_BYTES<P::secpar_v>);

            // copying the signature salt bytes to a new input block witness after digest bytes
            memcpy(witness + input_idx + VOLEMAYO_DIGEST_BYTES<P::secpar_v>, salt, VOLEMAYO_SALT_BYTES<P::secpar_v>);

            shake256_w(witness + witness_idx, witness + input_idx, VOLEKECCAK_MAYO_HASH_INPUT_BYTES<P::secpar_v>);
            
            // we need to manually add the padding from shake_w to the stored witness (for when the commitments are computed); needed for consistency
            witness[input_idx + VOLEMAYO_DIGEST_BYTES<P::secpar_v> + VOLEMAYO_SALT_BYTES<P::secpar_v>] = VOLEKECCAK_PADDING_D;
            witness[input_idx + VOLEKECCAK_RATE_BYTES - 1] = VOLEKECCAK_PADDING_0X80;
        #else
            size_t input_idx = OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS);
            size_t witness_idx = OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS + 1);

            // copying the digest bytes to a new input block witness
            memcpy(witness + input_idx, witness + (OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES*((VOLEKECCAK_NUM_ROUNDS) - 1)), VOLEMAYO_DIGEST_BYTES<P::secpar_v>);

            // copying the signature salt bytes to a new input block witness after digest bytes
            memcpy(witness + input_idx + VOLEMAYO_DIGEST_BYTES<P::secpar_v>, salt, VOLEMAYO_SALT_BYTES<P::secpar_v>);

            shake256_w(witness + witness_idx, witness + input_idx, VOLEKECCAK_MAYO_HASH_INPUT_BYTES<P::secpar_v>);
                
            // we need to manually add the padding from shake_w to the stored witness (for when the commitments are computed)
            witness[input_idx + VOLEMAYO_DIGEST_BYTES<P::secpar_v> + VOLEMAYO_SALT_BYTES<P::secpar_v>] = VOLEKECCAK_PADDING_D;
            witness[input_idx + VOLEKECCAK_RATE_BYTES - 1] = VOLEKECCAK_PADDING_0X80;

        #endif
    #endif

    #if defined WITH_RAINHASH
        std::array<uint8_t, VOLERAINHASH_B_BYTES> commit_input;
        memset((uint8_t*)commit_input.data(), 0xff, VOLERAINHASH_B_BYTES);

        size_t offset = 0;        
        // public
        memcpy((uint8_t*)commit_input.data() + offset, msg_hash, HASHED_MSG_SIZE_BYTES<P::secpar_v>);
        offset += HASHED_MSG_SIZE_BYTES<P::secpar_v>;
        // witness
        memcpy((uint8_t*)commit_input.data() + offset, opening, RAND_SIZE_BYTES<P::secpar_v>);

        // copying the input to the witness
        memcpy(witness, (uint8_t*)commit_input.data() + offset, VOLERAINHASH_B_BYTES);

        // the modified shake stores all intermediate values of S to witness.
        // the values start in witness + RAND_SIZE_BYTES<P::secpar_v> and are of length
        // - VOLEKECCAK_B_BYTES*((VOLEKECCAK_NUM_ROUNDS/6))
        // - or VOLEKECCAK_B_BYTES*(VOLEKECCAK_NUM_ROUNDS) for the non degree 16 version
        // the last block contains the last S, and from it the eventual hash value can be read

        uint8_t* rainhash_1_output_idx = (uint8_t*)witness + VOLERAINHASH_B_BYTES + VOLERAINHASH_B_BYTES*VOLERAINHASH_NUM_ROUNDS;
        rain_hash_with_sbox_output((uint8_t*)commit_input.data(), (uint8_t*)witness + VOLERAINHASH_B_BYTES, 
                                                rainhash_1_output_idx);

        uint8_t* rainhash_2_input_idx = rainhash_1_output_idx + VOLERAINHASH_B_BYTES;
        uint8_t* rainhash_2_witness_idx = rainhash_2_input_idx + VOLERAINHASH_B_BYTES;
        uint8_t* rainhash_2_output_idx = rainhash_2_witness_idx + VOLERAINHASH_B_BYTES * VOLERAINHASH_NUM_ROUNDS;     

        // Setting 0xff to the next rainhash input by default before override
        memset(rainhash_2_input_idx, 0xff, VOLERAINHASH_B_BYTES);
        // copying the digest bytes to a new input block witness
        memcpy(rainhash_2_input_idx, rainhash_1_output_idx, VOLEMAYO_DIGEST_BYTES<P::secpar_v>);
        // copying the signature salt bytes to a new input block witness after digest bytes
        memcpy(rainhash_2_input_idx + VOLEMAYO_DIGEST_BYTES<P::secpar_v>, salt, VOLEMAYO_SALT_BYTES<P::secpar_v>);                    
            
        rain_hash_with_sbox_output(rainhash_2_input_idx, rainhash_2_witness_idx, rainhash_2_output_idx);

        // std::cout << "rain witness input\n";
        // for (size_t i = 0; i < 64; i++) {
        //     std::cout << std::hex << static_cast<int>((rainhash_2_input_idx)[i]) << " ";
        // }
        // std::cout << "\n\n";

        // std::cout << "rain witness output\n";
        // for (size_t i = 0; i < 64; i++) {
        //     std::cout << std::hex << static_cast<int>((rainhash_2_output_idx)[i]) << " ";
        // }
        // std::cout << "\n\n";
    #endif
    
}

template <typename P>
#if defined WITH_KECCAK
void serialize_pk_sk(uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* packed_pk, 
                    uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* witness, uint8_t* packed_sk) {
#endif
#if defined WITH_RAINHASH
void serialize_pk_sk(uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* packed_pk, 
                    uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* witness, uint8_t* packed_sk) {
#endif

    #if defined WITH_KECCAK
    serialize_pk<P>(packed_pk, expanded_pk, msg_hash);
    #endif

    #if defined WITH_RAINHASH
    serialize_pk<P>(packed_pk, expanded_pk, msg_hash);
    #endif
    
    get_witness<P>(msg_hash, rand, salt, witness);

    serialize_sk<P>(packed_sk, packed_pk, s, witness);
}


template <typename P>
#if defined WITH_KECCAK
bool vole_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
#endif

#if defined WITH_RAINHASH
bool vole_prove(uint8_t* proof, const uint8_t* random_seed, size_t random_seed_len, 
                uint8_t* expanded_pk, uint8_t* msg_hash,
                uint8_t* rain_rc, uint8_t* rain_mat,
                uint8_t* s, uint8_t* rand, uint8_t* salt, uint8_t* r_additional) {
#endif
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    #if defined WITH_KECCAK
    std::array<uint8_t, VOLEKECCAK_WITNESS_SIZE_BYTES<P::secpar_v>> witness {}; 

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> packed_pk;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> packed_sk;
    
    serialize_pk_sk<P>(expanded_pk, msg_hash, (uint8_t*)packed_pk.data(), s, rand, salt, (uint8_t*)witness.data(), (uint8_t*)packed_sk.data());
    #endif

    #if defined WITH_RAINHASH
    std::array<uint8_t, VOLERAINHASH_WITNESS_SIZE_BYTES<P::secpar_v>> witness {}; 

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES> packed_pk;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLERAINHASH_SECRET_SIZE_BYTES<S>> packed_sk;
    
    serialize_pk_sk<P>(expanded_pk, msg_hash, (uint8_t*)packed_pk.data(), s, rand, salt, 
            (uint8_t*)witness.data(), (uint8_t*)packed_sk.data());
    #endif

    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // (r, iv^pre) <- H_3(mu || r)
    faest::block_secpar<S> seed; // r
    block128 iv_pre;
    faest::block128 iv;
    std::array<uint8_t, sizeof(seed) + sizeof(iv)> seed_iv_pre;
    hasher.init(S);
    if (random_seed) // rho (NB: spec assumes rho is always given and \lambda bit long)
            hasher.update(random_seed, random_seed_len);
    hasher.update_byte(3);
    hasher.finalize(seed_iv_pre.data(), sizeof(seed_iv_pre));
    memcpy(&seed, seed_iv_pre.data(), sizeof(seed));
    memcpy(&iv_pre, &seed_iv_pre[sizeof(seed)], sizeof(iv));

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_prove_1 iv_pre 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(iv_pre)[i] << "\n";
    // }

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(&iv_pre, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_prove_1 iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    block_secpar<S>* forest = reinterpret_cast<block_secpar<S>*>(
        aligned_alloc(alignof(block_secpar<S>), P::bavc_t::COMMIT_NODES * sizeof(block_secpar<S>)));
    unsigned char* hashed_leaves = reinterpret_cast<unsigned char*>(aligned_alloc(
        alignof(block_2secpar<S>), P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len));
    vole_block* u = reinterpret_cast<vole_block*>(
        aligned_alloc(alignof(vole_block), CP::VOLE_COL_BLOCKS * sizeof(vole_block)));
    vole_block* v = reinterpret_cast<vole_block*>(aligned_alloc(
        alignof(vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block)));    
    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    vole_commit<P>(seed, iv, forest, hashed_leaves, u, v, proof, vole_commit_check);

    // std::cout << "vole_prove_1 vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_prove_1 proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> chal1;
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> out;
    hasher.finalize(out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);
    memcpy(chal1.data(), out.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);      // getting the challenge
    
    faest::secret_key<P> sk;
    static_assert(faest::FAEST_PUBLIC_KEY_BYTES<P> > 0);
    uint8_t pk_packed[faest::FAEST_PUBLIC_KEY_BYTES<P>];
    if (!faest_unpack_sk_and_get_pubkey<P>((uint8_t*)packed_pk.data(), (uint8_t*)packed_sk.data(), &sk))
        return false;

    // SHAKE hash state the we will keep reusing.
    // faest::hash_state hasher;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    assert(sizeof(chal1) == CP::VOLE_CHECK::CHALLENGE_BYTES);
    hasher.update(chal1.data(), CP::VOLE_CHECK::CHALLENGE_BYTES);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";

    FAEST_ASSERT(proof
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES
        - CP::VOLE_COMMIT_SIZE);


    uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - ((proof + faest::VOLE_PROOF_BYTES<P>) 
    //     - P::grinding_counter_size
    //     - sizeof(iv_pre)
    //     - sizeof(faest::block_secpar<S>)
    //     - P::bavc_t::OPEN_SIZE
    //     - CP::QS::PROOF_BYTES
    //     - (OC::WITNESS_BITS + 7) / 8
    //     - P::CONSTS::VOLE_CHECK::PROOF_BYTES) << "\n";
    
    FAEST_ASSERT(proof + CP::VOLE_COMMIT_SIZE
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8
        - P::CONSTS::VOLE_CHECK::PROOF_BYTES);

    // vole_check_sender hashes u_tilde and V_tilde
    vole_check_sender<P>(u, v, chal1.data(), vole_check_proof, hasher);

    uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    FAEST_ASSERT(vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES
        - (OC::WITNESS_BITS + 7) / 8);

    size_t remainder = ((OC::WITNESS_BITS + 7) / 8) % (16 * CP::VOLE_BLOCK);
    for (size_t i = 0; i < CP::WITNESS_BLOCKS - (remainder != 0); ++i)
    {
        faest::vole_block correction_i = u[i] ^ sk.witness[i];
        memcpy(correction + i * sizeof(faest::vole_block), &correction_i, sizeof(faest::vole_block));
    }
    if (remainder)
    {
        faest::vole_block correction_i = u[CP::WITNESS_BLOCKS - 1] ^ sk.witness[CP::WITNESS_BLOCKS - 1];
        memcpy(correction + (CP::WITNESS_BLOCKS - 1) * sizeof(faest::vole_block), &correction_i,
               remainder);
    }

    // continue with H_2^2
    hasher.update(correction, (OC::WITNESS_BITS + 7) / 8);
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // std::cout << "vole_prove_1 chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[0] << std::endl;

    faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(aligned_alloc(
        alignof(faest::block_secpar<S>), CP::QUICKSILVER_ROWS_PADDED * sizeof(faest::block_secpar<S>)));

    memcpy(&u[0], &sk.witness[0], (OC::WITNESS_BITS + 7) / 8);
    static_assert(CP::QUICKSILVER_ROWS_PADDED % faest::TRANSPOSE_BITS_ROWS == 0, "");
    transpose_secpar<S>(v, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    free(v);

    faest::quicksilver_state<S, false, OC::QS_DEGREE> qs((uint8_t*)&u[0], macs, OC::OWF_NUM_CONSTRAINTS, chal2.data());

    faest::owf_constraints<P, false>(&qs, &sk.pk, chal2.data());

    uint8_t* qs_proof = correction + (OC::WITNESS_BITS + 7) / 8;
    FAEST_ASSERT(correction + (OC::WITNESS_BITS + 7) / 8
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE
        - CP::QS::PROOF_BYTES);

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.prove(OC::WITNESS_BITS, qs_proof, qs_check.data());
    free(macs);
    free(u);

    uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    FAEST_ASSERT(qs_proof + CP::QS::PROOF_BYTES 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>)
        - P::bavc_t::OPEN_SIZE);

    uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    FAEST_ASSERT(veccom_open_start + P::bavc_t::OPEN_SIZE 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre)
        - sizeof(faest::block_secpar<S>));

    uint8_t* iv_pre_dst = delta + sizeof(faest::block_secpar<S>);
    FAEST_ASSERT(delta + sizeof(faest::block_secpar<S>) 
    == (proof + faest::VOLE_PROOF_BYTES<P>) 
        - P::grinding_counter_size
        - sizeof(iv_pre));

    memcpy(iv_pre_dst, &iv_pre, sizeof(faest::block128));
    uint8_t* grinding_counter_dst = iv_pre_dst + sizeof(iv_pre);

    FAEST_ASSERT(iv_pre_dst + sizeof(iv_pre) 
    == proof + faest::VOLE_PROOF_BYTES<P> - P::grinding_counter_size);

    if constexpr (!P::use_grinding)
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2)
        hasher.init(S);
        hasher.update(chal2.data(), sizeof(chal2));
        hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
        hasher.update(qs_proof, CP::QS::PROOF_BYTES);
        hasher.update_byte(8 + 3);
        hasher.finalize(delta, sizeof(faest::block_secpar<S>));

        std::array<uint8_t, P::delta_bits_v> delta_bytes;
        faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

        P::bavc_t::open(forest, hashed_leaves, delta_bytes.data(), veccom_open_start);
    }
    else
    {
        // chall_3 <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 || ctr)
        // Initialize a 4x hasher and hash the common input prefix.
        faest::hash_state_x4 grinding_hasher;
        grinding_hasher.init(S);
        grinding_hasher.update_1(chal2.data(), sizeof(chal2));
        grinding_hasher.update_1(qs_check.data(), CP::QS::CHECK_BYTES);
        grinding_hasher.update_1(qs_proof, CP::QS::PROOF_BYTES);
        uint32_t counter;
        bool open_success = grind_and_open<typename P::bavc_t>(
            forest, hashed_leaves, delta, veccom_open_start, &grinding_hasher, &counter);
        // Opening fails with a negligible probability, so we can assume it succeeds.
        FAEST_ASSERT(open_success);
        if (!open_success) return false;
        // Store counter in the signature.
        grinding_counter_dst[0] = counter;
        grinding_counter_dst[1] = counter >> 8;
        grinding_counter_dst[2] = counter >> 16;
        grinding_counter_dst[3] = counter >> 24;
    }

    free(forest);
    free(hashed_leaves);

    // std::cout << "DIFF: " << proof + faest::VOLE_PROOF_BYTES<P> - grinding_counter_dst + P::grinding_counter_size << "\n";
    FAEST_ASSERT(grinding_counter_dst + P::grinding_counter_size == proof + faest::VOLE_PROOF_BYTES<P>);

    return true;

}

template <typename P>
#if defined WITH_KECCAK
bool vole_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, uint8_t* msg_hash, uint8_t* r_additional)
#endif
#if defined WITH_RAINHASH
bool vole_verify(const uint8_t* proof, size_t proof_size, uint8_t* expanded_pk, 
                uint8_t* msg_hash, uint8_t* rain_rc, uint8_t* rain_mat, uint8_t* r_additional)
#endif
{
    using CP = P::CONSTS;
    using OC = P::OWF_CONSTS;
    constexpr auto S = P::secpar_v;

    #if defined WITH_KECCAK
    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> packed_pk;
    serialize_pk<P>((uint8_t*)packed_pk.data(), expanded_pk, msg_hash);
    #endif

    #if defined WITH_RAINHASH
    uint8_t* packed_pk;
    packed_pk = (uint8_t*)malloc(faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES);
    memset(packed_pk, 0x00, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES);
    serialize_pk<P>(packed_pk, expanded_pk, msg_hash);
    #endif

    // std::cout << "vole_verify!!! \n" << std::flush;
    
    // SHAKE hash state the we will keep reusing.
    faest::hash_state hasher;

    // mu <- H_2^0(pk || msg)
    // faest::block_2secpar<S> mu;
    // hasher.init(S);
    // hasher.update(packed_pk, packed_pk_size);
    // hasher.update(commit_mu, commit_mu_size);
    // hasher.update_byte(8 + 0);
    // hasher.finalize(&mu, sizeof(mu));

    faest::block128 iv;

    const uint8_t* vole_check_proof = proof + CP::VOLE_COMMIT_SIZE;
    const uint8_t* correction = vole_check_proof + CP::VOLE_CHECK::PROOF_BYTES;
    const uint8_t* qs_proof = correction + OC::WITNESS_BITS / 8;
    const uint8_t* veccom_open_start = qs_proof + CP::QS::PROOF_BYTES;
    const uint8_t* delta = veccom_open_start + P::bavc_t::OPEN_SIZE;
    const uint8_t* iv_pre_ptr = delta + sizeof(faest::block_secpar<S>);
    const uint8_t* counter = iv_pre_ptr + sizeof(iv);

    // for (size_t i = 0; i < sizeof(iv); i++) {
    //     std::cout << "vole_verify iv_pre_ptr 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)iv_pre_ptr[i] << "\n";
    // }
    // std::cout << "vole_verify counter 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)counter[0] << "\n";

    // Check that the prover actually did its grinding.
    for (size_t i = secpar_to_bits(S) - 1; i >= CP::VEC_COM::delta_bits_v; --i)
        if ((delta[i / 8] >> (i % 8)) & 1)
            return false;

    // iv <- H_4(iv^pre)
    hasher.init(S);
    hasher.update(iv_pre_ptr, sizeof(iv));
    hasher.update_byte(4);
    hasher.finalize(reinterpret_cast<uint8_t*>(&iv), sizeof(iv));

    // std::cout << "vole_verify iv 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)reinterpret_cast<uint8_t*>(&iv)[0] << "\n";

    std::array<uint8_t, P::delta_bits_v> delta_bytes;
    faest::expand_bits_to_bytes(delta_bytes.data(), P::delta_bits_v, delta);

    faest::vole_block* q = reinterpret_cast<faest::vole_block*>(aligned_alloc(
        alignof(faest::vole_block), P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(faest::vole_block)));
    uint8_t vole_commit_check[CP::VOLE_COMMIT_CHECK_SIZE];

    if (!vole_reconstruct<P>(iv, q, delta_bytes.data(), proof, veccom_open_start,
                             vole_commit_check))
    {
        free(q);
        return false;
    }

    // std::cout << "vole_verify vole_commit_check 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)vole_commit_check[0] << "\n";
    // std::cout << "vole_verify proof 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)proof[0] << "\n";

    // Getting the additional r
    hasher.init(S);
    hasher.update(r_additional, 32);
    std::array<uint8_t, 32> r_additional_hash_out;
    hasher.finalize(r_additional_hash_out.data(), 32);

    // chall_1 <- H_2^1(mu || com || c_1 || ... || c_\tau-1 || iv)
    std::array<uint8_t, CP::VOLE_CHECK::CHALLENGE_BYTES> chal1;
    hasher.init(S);
    hasher.update(r_additional_hash_out.data(), 32);
    // hasher.update(&mu, sizeof(mu));
    hasher.update(vole_commit_check, CP::VOLE_COMMIT_CHECK_SIZE);
    hasher.update(proof, CP::VOLE_COMMIT_SIZE);
    hasher.update(&iv, sizeof(iv));
    hasher.update_byte(8 + 1);
    hasher.finalize(chal1.data(), sizeof(chal1));

    // std::cout << "vole_verify chal1 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal1[0] << std::endl;;

    // chall_2 <- H_2^2(chall_1 || \tilde{u} || h_V || d)
    std::array<uint8_t, CP::QS::CHALLENGE_BYTES> chal2;
    hasher.init(S);
    hasher.update(r_additional, 32);
    hasher.update(chal1.data(), sizeof(chal1));
    hasher.update(vole_check_proof, CP::VOLE_CHECK::PROOF_BYTES);

    // vole_check_receiver hashes D
    vole_check_receiver<P>(q, delta_bytes.data(), chal1.data(), vole_check_proof, hasher);

    // continue with H_2^2
    hasher.update(correction, OC::WITNESS_BITS / 8);
    hasher.update_byte(8 + 2);
    hasher.finalize(chal2.data(), sizeof(chal2));

    // std::cout << "vole_verify chal2 0x" << std::hex << std::setw(16) << std::setfill('0') << (size_t)chal2[0] << std::endl;;

    std::array<faest::vole_block, CP::WITNESS_BLOCKS> correction_blocks;
    memcpy(&correction_blocks, correction, OC::WITNESS_BITS / 8);
    memset(reinterpret_cast<uint8_t*>(correction_blocks.data()) + OC::WITNESS_BITS / 8, 0,
           sizeof(correction_blocks) - OC::WITNESS_BITS / 8);
    vole_receiver_apply_correction<P>(CP::WITNESS_BLOCKS, P::delta_bits_v, correction_blocks.data(), q,
                                      delta_bytes.data());

    faest::block_secpar<S>* macs = reinterpret_cast<faest::block_secpar<S>*>(
        aligned_alloc(alignof(faest::block_secpar<S>), CP::VOLE_ROWS_PADDED * sizeof(faest::block_secpar<S>)));
    transpose_secpar<S>(q, macs, CP::VOLE_COL_STRIDE, CP::QUICKSILVER_ROWS_PADDED);
    free(q);

    faest::block_secpar<S> delta_block;
    memcpy(&delta_block, delta, sizeof(delta_block));

    faest::public_key<P> pk;
    #if defined WITH_KECCAK
        faest_unpack_public_key(&pk, (uint8_t*)packed_pk.data());
    #endif
    #if defined WITH_RAINHASH
        faest_unpack_public_key(&pk, packed_pk);
    #endif

    faest::quicksilver_state<S, true, OC::QS_DEGREE> qs(macs, OC::OWF_NUM_CONSTRAINTS, delta_block, chal2.data());

    faest::owf_constraints<P, true>(&qs, &pk, chal2.data());

    std::array<uint8_t, CP::QS::CHECK_BYTES> qs_check;
    qs.verify(OC::WITNESS_BITS, qs_proof, qs_check.data());
    free(macs);

    // chall_3' <- H_2^3(chall_2 || \tilde{a}_0 || \tilde{a}_1 || \tilde{a}_2 [|| ctr])
    faest::block_secpar<S> delta_check;
    hasher.init(S);
    hasher.update(chal2.data(), sizeof(chal2));
    hasher.update(qs_check.data(), CP::QS::CHECK_BYTES);
    hasher.update(qs_proof, CP::QS::PROOF_BYTES);
    if constexpr (P::use_grinding)
    {
        hasher.update(counter, P::grinding_counter_size);
    }
    hasher.update_byte(8 + 3);
    hasher.finalize(&delta_check, sizeof(delta_check));

    return memcmp(delta, &delta_check, sizeof(delta_check)) == 0;

}


} // namespace faest

#endif
