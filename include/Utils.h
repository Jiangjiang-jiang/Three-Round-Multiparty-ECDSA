//
// Created by qsang on 24-10-12.
//

#ifndef UTILS_H
#define UTILS_H

#include <set>
#include <unordered_map>
#include <vector>
#include "bicycl/bicycl.hpp"

using namespace BICYCL;
using Commitment = OpenSSL::HashAlgo::Digest;
using CommitmentSecret = std::vector<unsigned char>;

void randomize_message(std::vector<unsigned char>& m);
Mpz factorial(size_t n);
Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta);
OpenSSL::BN lagrange_at_zero(const OpenSSL::ECGroup &E, const std::set<size_t>& S, size_t i);
std::set<size_t> select_parties(RandGen& rng, size_t n, size_t t);

// Data structures for different rounds of the protocol.
struct RoundOneData {
    size_t id;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    RoundOneData(const size_t id, const CL_HSMqk::CipherText& share, const Commitment& com_i, const CL_HSMqk_ZKAoKProof& proof) : id(id), enc_phi_share(share), com_i(com_i), zk_proof_cl_enc(proof) {}
};

struct RoundOneLocalData {
    size_t id;
    OpenSSL::BN phi_share;
    OpenSSL::BN k_share;
    OpenSSL::ECPoint R_share;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CommitmentSecret open_i;
    std::unordered_map<size_t, Commitment> com_list;
    ECNIZKProof zk_proof_dl;

    RoundOneLocalData(const size_t id, const OpenSSL::ECGroup& E, const OpenSSL::BN& phi, const OpenSSL::BN& k, const OpenSSL::ECPoint& R, const CL_HSMqk::CipherText& ct, const Commitment& com_i, const CommitmentSecret& open_i, const ECNIZKProof& zk_proof)
        : id(id), phi_share(phi), k_share(k), R_share(E, R), enc_phi_share(ct), com_i(com_i), open_i(open_i), zk_proof_dl(E, zk_proof)
    {
        com_list.emplace(this->id, com_i);
    }
};

struct RoundTwoData {
    size_t id;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;
    OpenSSL::ECPoint Ri;
    CommitmentSecret open_i;
    ECNIZKProof zk_proof_dl;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    RoundTwoData(const size_t id, const OpenSSL::ECGroup& E, const CL_HSMqk::CipherText& phi_x, const CL_HSMqk::CipherText& phi_k, const OpenSSL::ECPoint& R, const CommitmentSecret& open_i, const ECNIZKProof& zk_proof_dl, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_x, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_k)
        : id(id), phi_x_share(phi_x), phi_k_share(phi_k), Ri(E, R), open_i(open_i), zk_proof_dl(E, zk_proof_dl), zk_proof_dl_cl_x(E, zk_proof_dl_cl_x), zk_proof_dl_cl_k(E, zk_proof_dl_cl_k) {}
};

struct RoundTwoLocalData {
    size_t id;
    CL_HSMqk::CipherText enc_phi;

    RoundTwoLocalData(const size_t id, const CL_HSMqk::CipherText& phi)
        : id(id), enc_phi(phi) {}
};

struct RoundThreeData {
    size_t id;
    QFI c0_dec_share;
    QFI c1_dec_share;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1;

    RoundThreeData(const size_t id, const QFI& c0_dec_share, const QFI& c1_dec_share, const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c0, const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c1)
        : id(id), c0_dec_share(c0_dec_share), c1_dec_share(c1_dec_share), zk_proof_pd_c0(zk_proof_pd_c0), zk_proof_pd_c1(zk_proof_pd_c1) {}
};

struct RoundThreeLocalData {
    size_t id;
    CL_HSMqk::CipherText c0;
    CL_HSMqk::CipherText c1;
    OpenSSL::BN rx;

    RoundThreeLocalData(const size_t id, const CL_HSMqk::CipherText& c0, const CL_HSMqk::CipherText& c1, const OpenSSL::BN& rx)
        : id(id), c0(c0), c1(c1), rx(rx) {}
};

struct Signature {
    OpenSSL::BN rx;
    OpenSSL::BN s;

    Signature(const OpenSSL::BN& rx, const OpenSSL::BN& s) : rx(rx), s(s) {}
};

// Class holding group parameters for the protocol.
class GroupParams {
public:
    SecLevel sec_level;
    size_t n;
    size_t t;
    Mpz delta;
    OpenSSL::ECGroup ec_group;
    OpenSSL::HashAlgo H;
    CL_HSMqk cl_pp;

    GroupParams(SecLevel seclevel, size_t n, size_t t, RandGen& randgen)
    : sec_level(seclevel), n(n), t(t), delta(factorial(n)), ec_group(seclevel), H(seclevel), cl_pp(ec_group.order(), 1, seclevel, randgen) {}
};

#endif //UTILS_H
