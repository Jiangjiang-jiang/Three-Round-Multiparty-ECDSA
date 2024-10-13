//
// Created by qsang on 24-10-12.
//
#include <cmath>
#include <set>
#include <vector>
#include <numeric>
#include <algorithm>
#include "Protocol.h"

Protocol::Protocol(GroupParams& params) : params(params) { S.reserve(params.n); }

void Protocol::dkg()
{
    RandGen randgen;
    const CL_HSMqk& cl_pp = params.cl_pp;
    const OpenSSL::ECGroup& ec_group = params.ec_group;
    const size_t n = params.n;
    const size_t t = params.t;
    const Mpz& delta = params.delta;

    Mpz coff_bound;
    size_t ell = cl_pp.secretkey_bound().nbits() - static_cast<size_t>(floor(log2(static_cast<double>(n)))) * t * n - cl_pp.lambda_distance() - 2;
    Mpz::mulby2k(coff_bound, Mpz("1"), ell);
    std::cout << coff_bound << std::endl;
    std::cout << cl_pp.secretkey_bound() << std::endl;

    std::vector<CL_HSMqk::SecretKey> sk_list;
    std::vector<Mpz> sk_list_mpz;
    std::vector<CL_HSMqk::PublicKey> pk_list;
    sk_list.reserve(n);
    sk_list_mpz.reserve(n);
    pk_list.reserve(n);

    Mpz alpha(randgen.random_mpz(coff_bound));

    Mpz cl_u, sk;
    Mpz::mul(cl_u, alpha, delta);
    Mpz::mul(sk, cl_u, delta);

    CL_HSMqk::SecretKey sk_delta(cl_pp, sk);
    CL_HSMqk::PublicKey pk = cl_pp.keygen(sk_delta);

    std::vector<Mpz> cl_coefficient;
    cl_coefficient.reserve(t);

    for (std::size_t k = 0; k < t; ++k) {
        cl_coefficient.emplace_back(randgen.random_mpz(coff_bound));
    }

    for (std::size_t j = 0; j < n; ++j) {
        Mpz skj = cl_coefficient[t-1];
        for (std::size_t k = t-1; k > 0; --k) {
            Mpz::mul(skj, skj, Mpz(j+1));
            Mpz::add(skj, skj, cl_coefficient[k-1]);
        }
        Mpz::mul(skj, skj, Mpz(j+1));
        Mpz::add(skj, skj, cl_u);
        sk_list_mpz.push_back(skj);
        sk_list.emplace_back(cl_pp, skj);
        pk_list.emplace_back(cl_pp, sk_list.back());
    }

    Mpz cl_ut(0UL);
    std::set<size_t> SS;
    while(SS.size() <= t) {
        SS.insert(randgen.random_ui(n));
    }
    for (size_t s : SS) {
        Mpz cl_l = cl_lagrange_at_zero(SS, s, delta);
        Mpz::mul(cl_l, cl_l, sk_list_mpz[s]);
        Mpz::add(cl_ut, cl_ut, cl_l);
    }
    if (sk == cl_ut) {
        std::cout << "CL verify success" << std::endl;
    }

    // For ECDSA DKG
    std::vector<OpenSSL::BN> xi_list(n);
    OpenSSL::BN u(ec_group.random_mod_order());
    OpenSSL::ECPoint X(ec_group, u);
    std::vector<OpenSSL::BN> coefficient;
    std::vector<OpenSSL::ECPoint> coefficient_group;
    coefficient.reserve(t);
    coefficient_group.reserve(t);

    for (std::size_t k = 0; k < t; ++k) {
        coefficient.push_back(ec_group.random_mod_order());
        coefficient_group.emplace_back(ec_group, coefficient.back());
    }

    for (std::size_t j = 0; j < n; ++j) {
        xi_list[j] = coefficient[t-1];
        for (std::size_t k = t-1; k > 0; --k) {
            ec_group.mul_by_word_mod_order(xi_list[j], j+1);
            ec_group.add_mod_order(xi_list[j], xi_list[j], coefficient[k-1]);
        }
        ec_group.mul_by_word_mod_order(xi_list[j], j+1);
        ec_group.add_mod_order(xi_list[j], xi_list[j], u);
    }

    std::vector<OpenSSL::ECPoint> Xi_list;
    Xi_list.reserve(n);
    OpenSSL::ECPoint T1(ec_group);
    for (const auto& xi : xi_list) {
        ec_group.scal_mul_gen(T1, xi);
        Xi_list.emplace_back(ec_group, T1);
    }

    OpenSSL::BN ut(0UL);
    for (std::size_t s = 0; s < n; ++s) {
        OpenSSL::BN l = lagrange_at_zero(ec_group, n, s);
        ec_group.mul_mod_order(l, l, xi_list[s]);
        ec_group.add_mod_order(ut, ut, l);
    }
    if (u != ut) {
        std::cout << "cannot reconstruct u from secret {xi}";
    }

    for(std::size_t i = 0; i < n; ++i) {
        S.emplace_back(params, i+1, pk, pk_list, sk_list[i], X, Xi_list, xi_list[i]);
    }
}

bool Protocol::run() {
    const size_t n = params.n;

    std::vector<RoundOneData> data_set_for_one;
    std::vector<RoundTwoData> data_set_for_two;
    std::vector<RoundThreeData> data_set_for_three;
    std::vector<Signature> data_set_for_offline;

    data_set_for_one.reserve(n);
    data_set_for_two.reserve(n);
    data_set_for_three.reserve(n);
    data_set_for_offline.reserve(n);

    // Round 1
    for(auto& party : S) {
        party.handleRoundOne();
        data_set_for_one.push_back(party.getRoundOneData());
    }

    // Round 2
    for(auto& party : S) {
        party.handleRoundTwo(data_set_for_one);
        data_set_for_two.push_back(party.getRoundTwoData());
    }

    // Round 3
    std::vector<unsigned char> message;
    randomize_message(message);
    for(auto& party : S) {
        party.handleRoundThree(data_set_for_two, message);
        data_set_for_three.push_back(party.getRoundThreeData());
    }

    // Offline
    for(auto& party : S) {
        party.handleOffline(data_set_for_three);
        data_set_for_offline.push_back(party.getSignature());
    }

    return std::all_of(S.begin(), S.end(), [&](const auto& party) {
        return party.verify(data_set_for_offline[&party - &S[0]], message);
    });
}
