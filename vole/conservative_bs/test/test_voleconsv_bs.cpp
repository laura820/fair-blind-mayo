#include <array>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

// faest files
#include "faest_keys.hpp"
#include "owf_proof.hpp"
// #include "vole_proof/vole.cpp"
#include "faest.cpp"
#include "test.hpp"
#include <memory>



#if defined WITH_KECCAK

TEST_CASE("volekeccak_then_mayo prove v2_128_s", "[volekeccak_then_mayo prove v2_128_s]")
{
    std::cout << "\nRunning volekeccak_then_mayo prove v2_128_s\n";
    using P = faest::v2::keccak_then_mayo_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> sk_packed;

    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());

    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();

    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);

}


TEST_CASE("volekeccak_then_mayo vole_prove v2_128_s", "[volekeccak_then_mayo vole_prove v2_128_s]")
{
    std::cout << "\nRunning volekeccak_then_mayo prove v2_128_s\n";
    using P = faest::v2::keccak_then_mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLEKECCAK_SECRET_SIZE_BYTES<S>> sk_packed;

    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());

    public_key<P> pk;
    secret_key<P> sk;

    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    uint8_t* s = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_WITNESS_SIZE_BYTES<S>;
    uint8_t* rand = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>;
    #if defined KECCAK_DEG_16
    uint8_t* salt = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS/6) + VOLEMAYO_DIGEST_BYTES<P::secpar_v>;
    #else
    uint8_t* salt = sk_packed.data() + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + OPENING_SIZE_BYTES<P::secpar_v> + VOLEKECCAK_B_BYTES * (VOLEKECCAK_NUM_ROUNDS) + VOLEMAYO_DIGEST_BYTES<P::secpar_v>;
    #endif

    uint8_t random_seed = 0;

    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);

    vole_prove<P>(
        (uint8_t*)&proof, 
        &random_seed, 
        0, 
        (uint8_t*)&pk.mayo_expanded_pk,
        (uint8_t*)&pk.msg, 
        s,
        rand,
        salt, 
        (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0


    bool ret = vole_verify<P>(
        (uint8_t*)&proof, 
        VOLE_PROOF_BYTES<P>, 
        (uint8_t*)&pk.mayo_expanded_pk, 
        (uint8_t*)&pk.msg,
        (uint8_t*)&r_additional);


    REQUIRE(ret == true);

}

#endif


#if defined WITH_RAINHASH

TEST_CASE("volerainhash_then_mayo prove v2_128_s", "[volerainhash_then_mayo prove v2_128_s]")
{
    std::cout << "\nRunning volerainhash_then_mayo prove v2_128_s\n";
    using P = faest::v2::rainhash_then_mayo_128_s;
    constexpr auto S = P::secpar_v;

    public_key<P> pk;
    secret_key<P> sk;

    std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S>> pk_packed;
    std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLERAINHASH_SECRET_SIZE_BYTES<S>> sk_packed;

    test_gen_keypair<P>(pk_packed.data(), sk_packed.data());

    faest_unpack_public_key<P>(&pk, pk_packed.data());
    faest_unpack_secret_key<P>(&sk, sk_packed.data());

    const auto delta = rand<faest::block_secpar<S>>();

    quicksilver_test_state<S> qs_test(P::OWF_CONSTS::OWF_NUM_CONSTRAINTS,
                                        reinterpret_cast<uint8_t*>(sk.witness),
                                        P::OWF_CONSTS::WITNESS_BITS, delta);

    auto& qs_state_prover = qs_test.prover_state;
    auto& qs_state_verifier = qs_test.verifier_state;
    
    assert(&qs_state_verifier != nullptr);
    assert(&pk != nullptr);

    owf_constraints<P, false>(&qs_state_prover, &sk.pk, (unsigned char*) &pk);
    owf_constraints<P, true>(&qs_state_verifier, &pk, (unsigned char*) &pk);

    auto [check_prover, check_verifier] = qs_test.compute_check();
    REQUIRE(check_prover == check_verifier);


}

TEST_CASE("volerainhash_then_mayo vole_prove v2_128_s", "[volerainhash_then_mayo vole_prove v2_128_s]")
{
    std::cout << "\nRunning volerainhash_then_mayo prove v2_128_s\n";
    using P = faest::v2::rainhash_then_mayo_128_s;
    using CP = P::CONSTS;
    constexpr auto S = P::secpar_v;

    // std::vector<uint8_t> proof((int)faest::VOLE_PROOF_BYTES<P>);
    uint8_t proof[faest::VOLE_PROOF_BYTES<P>];
    memset(proof, 0x00, faest::VOLE_PROOF_BYTES<P>);

    uint8_t* pk_packed;
    pk_packed = (uint8_t*)malloc(faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES);
    memset(pk_packed, 0x00, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES);

    uint8_t* sk_packed;
    sk_packed = (uint8_t*)malloc(faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLERAINHASH_SECRET_SIZE_BYTES<S>);
    memset(sk_packed, 0x00, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLERAINHASH_SECRET_SIZE_BYTES<S>);

    // std::array<uint8_t, faest::VOLEMAYO_PUBLIC_SIZE_BYTES<S> + VOLERAINHASH_PUBLIC_SIZE_BYTES> pk_packed;
    // std::array<uint8_t, faest::VOLEMAYO_SECRET_SIZE_BYTES<S> + VOLERAINHASH_SECRET_SIZE_BYTES<S>> sk_packed;

    test_gen_keypair<P>(pk_packed, sk_packed);

    public_key<P> pk;
    secret_key<P> sk;

    faest_unpack_public_key<P>(&pk, pk_packed);
    faest_unpack_secret_key<P>(&sk, sk_packed);

    uint8_t* s = sk_packed + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_PUBLIC_SIZE_BYTES + VOLERAINHASH_WITNESS_SIZE_BYTES<S>;
    uint8_t* rand = sk_packed + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_PUBLIC_SIZE_BYTES;

    uint8_t* salt = sk_packed + VOLEMAYO_PUBLIC_SIZE_BYTES<P::secpar_v>  + VOLERAINHASH_PUBLIC_SIZE_BYTES
            + RAND_SIZE_BYTES<P::secpar_v> + VOLERAINHASH_B_BYTES * (VOLERAINHASH_NUM_ROUNDS) + VOLEMAYO_DIGEST_BYTES<P::secpar_v>;

    uint8_t random_seed = 0;

    std::vector<uint8_t> r_additional(32);
    memset(r_additional.data(), 0xff, 32);

    vole_prove<P>(
        (uint8_t*)&proof, 
        &random_seed, 
        0, 
        (uint8_t*)&pk.mayo_expanded_pk,
        (uint8_t*)&pk.msg, 
        (uint8_t*)&pk.rain_rc_qs,
        (uint8_t*)&pk.rain_mat_qs,
        s,
        rand,
        salt,
        (uint8_t*)&r_additional);     // For now setting random seed and random seed length to NULL and 0


    bool ret = vole_verify<P>(
    (uint8_t*)&proof, 
    VOLE_PROOF_BYTES<P>, 
    (uint8_t*)&pk.mayo_expanded_pk, 
    (uint8_t*)&pk.msg,
    (uint8_t*)&pk.rain_rc_qs,
    (uint8_t*)&pk.rain_mat_qs,
    (uint8_t*)&r_additional);


    REQUIRE(ret == true);

}

#endif
