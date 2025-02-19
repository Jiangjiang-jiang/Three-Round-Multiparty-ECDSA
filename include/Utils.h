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
    QFI c1;
    std::vector<QFI> c2s;
    CL_HSMqk_PolyVerify_ZKProof zk_proof_poly;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    RoundOneData(const size_t id, const CL_HSMqk::CipherText& share, const CL_HSMqk_ZKAoKProof& proof, const QFI& c1, const std::vector<QFI>& c2s, const CL_HSMqk_PolyVerify_ZKProof& zk_proof_poly) : id(id), enc_phi_share(share), zk_proof_cl_enc(proof), c1(c1), c2s(c2s), zk_proof_poly(zk_proof_poly) {}

    size_t getSize(){
        size_t b = 0;
        b += sizeof(id);
        b += enc_phi_share.get_bytes();
        b += c1.get_bytes();
        for(auto& c2: c2s){
            b += c2.get_bytes();
        }
        b += zk_proof_poly.get_bytes();
        b += zk_proof_cl_enc.get_bytes();
       return b;
    }
};

struct RoundOneLocalData {
    size_t id;
    OpenSSL::BN phi_share;
    OpenSSL::BN k_share;
    CL_HSMqk::CipherText enc_phi_share;

    RoundOneLocalData(const size_t id, const OpenSSL::BN& phi, const OpenSSL::BN& k, const CL_HSMqk::CipherText& ct)
        : id(id), phi_share(phi), k_share(k), enc_phi_share(ct) {}
};

struct RoundTwoData {
    size_t id;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;
    OpenSSL::ECPoint Ri;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    RoundTwoData(const size_t id, const OpenSSL::ECGroup& E, const CL_HSMqk::CipherText& phi_x, const CL_HSMqk::CipherText& phi_k, const OpenSSL::ECPoint& R, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_x, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_k)
        : id(id), phi_x_share(phi_x), phi_k_share(phi_k), Ri(E, R), zk_proof_dl_cl_x(E, zk_proof_dl_cl_x), zk_proof_dl_cl_k(E, zk_proof_dl_cl_k) {}

    size_t getSize() {
        size_t b = 0;
        b += sizeof(id);
        b += phi_x_share.get_bytes();
        b += phi_k_share.get_bytes();
        b += Ri.get_bytes();
        b += zk_proof_dl_cl_k.get_bytes_dl();
        b += zk_proof_dl_cl_x.get_bytes_dl();
        return b;
    }
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

    size_t getSize() {
        size_t b = 0;
        b += sizeof(id);
        b += c0_dec_share.get_bytes();
        b += c1_dec_share.get_bytes();
        b += zk_proof_pd_c0.get_bytes();
        b += zk_proof_pd_c1.get_bytes();
        return b;
    }
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
