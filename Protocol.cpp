//
// Created by qsang on 24-10-12.
//

#include "Protocol.h"

void Protocol::dkg()
{
    /*// For CL
    RandGen randgen;
    std::vector<CL_HSMqk::SecretKey> sk_v;
    sk_v.reserve(params.n);
    std::vector<CL_HSMqk::PublicKey> pk_v;
    pk_v.reserve(params.n);

    for (unsigned int i = 0; i < params.n; i++)
    {
        CL_HSMqk::SecretKey ski = params.cl_pp.keygen(randgen);
        CL_HSMqk::PublicKey pki = params.cl_pp.keygen(ski);
        sk_v.push_back(ski);
        pk_v.push_back(pki);
    }

    CL_HSMqk::SecretKey sk = sk_v[0];
    for (unsigned int i = 1; i < params.n; i++)
    {
        CL_HSMqk::SecretKey::add(sk, sk, sk_v[i]);
    }

    CL_HSMqk::PublicKey pk = params.cl_pp.keygen(sk);
    // pk, pk_v, sk_v -> pk, [pk1,...,pkn], [sk1,...,skn]*/


    RandGen randgen;
    unsigned long ell =  params.cl_pp.secretkey_bound().nbits() - std::floor(log2(params.n)) * params.t - params.cl_pp.lambda_distance() + 2;
    Mpz coff_bound;
    Mpz::mulby2k (coff_bound, Mpz("1"), ell);
    std::cout << coff_bound << std::endl;
    std::cout << params.cl_pp.secretkey_bound() << std::endl;

    std::vector<CL_HSMqk::SecretKey> sk_v;
    std::vector<Mpz> sk_v_mpz;
    std::vector<CL_HSMqk::PublicKey> pk_v;

    Mpz delta = factorial(params.n);
    Mpz alpha (randgen.random_mpz(coff_bound));

    Mpz cl_u, sk;
    Mpz::mul(cl_u, alpha, delta);
    Mpz::mul(sk, cl_u, delta);
    CL_HSMqk::SecretKey sk_delta (params.cl_pp, sk);
    CL_HSMqk::PublicKey pk = params.cl_pp.keygen(sk_delta);


    std::vector<Mpz> cl_coefficient; /* t scalars a_i,k */
    cl_coefficient.reserve (params.t);

    for (unsigned int k = 0; k < params.t; k++)
    {
        cl_coefficient.emplace_back(randgen.random_mpz(coff_bound));
    }

    for (unsigned int j = 0; j < params.n; j++)
    {
        Mpz skj;
        skj = cl_coefficient[params.t-1];
        for (unsigned int k = params.t-1; k > 0; k--)
        {
            Mpz::mul(skj, skj, j+1);
            Mpz::add(skj, skj, cl_coefficient[k-1]);
        }
        Mpz::mul(skj, skj, j+1);
        Mpz::add(skj, skj, cl_u);
        CL_HSMqk::SecretKey sk (params.cl_pp, skj);
        sk_v_mpz.push_back(skj);
        sk_v.push_back(sk);
        pk_v.emplace_back(CL_HSMqk::PublicKey(params.cl_pp, sk));
    }

    Mpz cl_ut(0UL), cl_l;
    std::set<unsigned int> SS;
    while(SS.size() <= params.t)
    {
        SS.insert(randgen.random_ui(params.n));
    }
    for (unsigned int s : SS)
    {
        cl_l = cl_lagrange_at_zero(params.cl_pp, SS, s, delta);
        Mpz::mul(cl_l, cl_l, sk_v_mpz[s]);
        Mpz::add(cl_ut, cl_ut, cl_l);
    }
    if (sk == cl_ut)
    {
        std::cout << "CL verify success" << std::endl;
    }

    // For ECDSA
    std::vector<OpenSSL::BN> xi_v;
    xi_v.resize(params.n);
    OpenSSL::BN u (params.ec_group.random_mod_order());
    OpenSSL::ECPoint X(params.ec_group, u);
    std::vector<OpenSSL::BN> coefficient;
    coefficient.reserve (params.t);
    std::vector<OpenSSL::ECPoint> coefficient_group;
    coefficient_group.reserve (params.t);
    for (unsigned int k = 0; k < params.t; k++)
    {
        coefficient.push_back (params.ec_group.random_mod_order());
        coefficient_group.push_back (OpenSSL::ECPoint (params.ec_group, coefficient[k]));
    }

    for (unsigned int j = 0; j < params.n; j++)
    {
        xi_v[j] = coefficient[params.t-1];
        for (unsigned int k = params.t-1; k > 0; k--)
        {
            params.ec_group.mul_by_word_mod_order (xi_v[j], j+1);
            params.ec_group.add_mod_order (xi_v[j], xi_v[j], coefficient[k-1]);
        }
        params.ec_group.mul_by_word_mod_order (xi_v[j], j+1);
        params.ec_group.add_mod_order (xi_v[j], xi_v[j], u);
    }

    std::vector<OpenSSL::ECPoint> Xi_v;
    OpenSSL::ECPoint T1 (params.ec_group);
    for (unsigned int j = 0; j < params.n; j++)
    {
        params.ec_group.scal_mul_gen (T1, xi_v[j]);
        Xi_v.push_back(OpenSSL::ECPoint (params.ec_group, T1));
    }

    OpenSSL::BN ut(0UL), l;
    for (unsigned int s = 0; s < params.n; ++s)
    {
        l = lagrange_at_zero (params.ec_group, params.n, s);
        params.ec_group.mul_mod_order (l, l, xi_v[s]);
        params.ec_group.add_mod_order (ut, ut, l);
    }
    if (u != ut)
    {
        std::cout << "cannot reconstruct u from secret {xi}";
    }

    for(unsigned int i = 0; i < params.n; ++i)
    {
        S.emplace_back(params, i+1, pk, pk_v, sk_v[i], X, Xi_v, xi_v[i]);
    }
}

bool Protocol::run()
{
    // For round 1
    std::vector<RoundOneData> data_set_for_one;
    for(unsigned int i = 0; i < params.n; ++i)
    {
        S[i].handleRoundOne();
        data_set_for_one.push_back(S[i].getRoundOneData());
    }

    // For round 2
    std::vector<RoundTwoData> data_set_for_two;
    for(unsigned int i = 0; i < params.n; ++i)
    {
        S[i].handleRoundTwo(data_set_for_one);
        data_set_for_two.push_back(S[i].getRoundTwoData());
    }

    // For round 3
    std::vector<RoundThreeData> data_set_for_three;
    std::vector<unsigned char> message;
    randomize_message(message);
    for(unsigned int i = 0; i < params.n; ++i)
    {
        S[i].handleRoundThree(data_set_for_two, message);
        data_set_for_three.push_back(S[i].getRoundThreeData());
    }

    // For offline
    std::vector<Signature> data_set_for_offline;
    for(unsigned int i = 0; i < params.n; ++i)
    {
        S[i].handleOffline(data_set_for_three);
        data_set_for_offline.push_back(S[i].getSignature());
    }

    bool flag = true;
    for(unsigned int i = 0; i < params.n; ++i)
    {
        flag &= S[i].verify(data_set_for_offline[i], message);
    }
    return flag;
}
