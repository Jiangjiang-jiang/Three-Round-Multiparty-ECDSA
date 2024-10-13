//
// Created by qsang on 24-10-12.
//

#ifndef PARTY_H
#define PARTY_H

#include "Utils.h"

class Party
{
public:
    Party(GroupParams& params, size_t id, const CL_HSMqk::PublicKey& pk, const std::vector<CL_HSMqk::PublicKey>& pki_v, const CL_HSMqk::SecretKey& ski, const OpenSSL::ECPoint& X, std::vector<OpenSSL::ECPoint> &X_v, const OpenSSL::BN& xi);

    const RoundOneData& getRoundOneData() const;
    RoundTwoData getRoundTwoData() const;
    const RoundThreeData& getRoundThreeData() const;
    const Signature& getSignature() const;

    std::tuple<Commitment, CommitmentSecret> commit(const OpenSSL::ECPoint &Q) const;
    std::tuple<Commitment, CommitmentSecret> commit(const OpenSSL::ECPoint &Q1, const OpenSSL::ECPoint &Q2) const;
    bool open(const Commitment &c, const OpenSSL::ECPoint &Q, const CommitmentSecret &r) const;
    bool open(const Commitment &c, const OpenSSL::ECPoint &Q1, const OpenSSL::ECPoint &Q2, const CommitmentSecret &r) const;

    void handleRoundOne();
    void handleRoundTwo(std::vector<RoundOneData>& data);
    void handleRoundThree(std::vector<RoundTwoData>& data, std::vector<unsigned char>& m);
    void handleOffline(std::vector<RoundThreeData>& data);
    bool verify(const Signature& signature, const std::vector<unsigned char>& m) const;

private:
    void partial_decrypt(const CL_HSMqk &pp, const CL_HSMqk::SecretKey &ski, CL_HSMqk::CipherText &encrypted_message, QFI &part_dec);
    CL_HSMqk::ClearText agg_partial_ciphertext(std::unordered_map<size_t, QFI>& decryptions, CL_HSMqk::CipherText &c) const;

    std::unique_ptr<RoundOneData> round1Data = nullptr;
    std::unique_ptr<RoundOneLocalData> round1LocalData = nullptr;
    std::unique_ptr<RoundTwoData> round2Data = nullptr;
    std::unique_ptr<RoundTwoLocalData> round2LocalData = nullptr;
    std::unique_ptr<RoundThreeData> round3Data = nullptr;
    std::unique_ptr<RoundThreeLocalData> round3LocalData = nullptr;

    std::unique_ptr<Signature> signature = nullptr;

    GroupParams& params;
    unsigned int id;
    CL_HSMqk::PublicKey pk;
    std::vector<CL_HSMqk::PublicKey> pki_v;
    std::vector<OpenSSL::ECPoint> Xi_v;
    OpenSSL::ECPoint X;

    CL_HSMqk::SecretKey ski;
    OpenSSL::BN xi;
};

#endif //PARTY_H
