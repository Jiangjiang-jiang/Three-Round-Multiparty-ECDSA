//
// Created by qsang on 24-10-12.
//

#ifndef PARTY_H
#define PARTY_H

#include "Utils.h"

class Party
{
public:
    Party(GroupParams& params, size_t id, const CL_HSMqk::PublicKey& pk, const std::vector<CL_HSMqk::PublicKey>& pki_vector, const CL_HSMqk::SecretKey& ski, const OpenSSL::ECPoint& X, std::vector<OpenSSL::ECPoint> &X_v, const OpenSSL::BN& xi);

    const RoundOneData& getRoundOneData() const;
    RoundTwoData getRoundTwoData() const;
    const RoundThreeData& getRoundThreeData() const;
    const Signature& getSignature() const;
    void setPartySet(const std::set<size_t>& party_set);

    void handleRoundOne(RoundOneData** send_data);
    void handleRoundTwo(const std::vector<RoundOneData*>& round_one_data, RoundTwoData** send_data);
    void handleRoundThree(const std::vector<RoundTwoData*>& round_two_data, const std::vector<unsigned char>& m, RoundThreeData** send_data);
    void handleOffline(const std::vector<RoundThreeData*>& data, Signature** send_data);
    bool verify(const Signature& signature, const std::vector<unsigned char>& m) const;

private:
    void partial_decrypt(const CL_HSMqk::SecretKey &ski, const CL_HSMqk::CipherText &encrypted_message, QFI &part_dec);
    CL_HSMqk::ClearText agg_partial_ciphertext(const std::unordered_map<size_t, QFI>& pd_map, const CL_HSMqk::CipherText &c) const;

    std::unique_ptr<RoundOneData> round1Data = nullptr;
    std::unique_ptr<RoundOneLocalData> round1LocalData = nullptr;
    std::unique_ptr<RoundTwoData> round2Data = nullptr;
    std::unique_ptr<RoundTwoLocalData> round2LocalData = nullptr;
    std::unique_ptr<RoundThreeData> round3Data = nullptr;
    std::unique_ptr<RoundThreeLocalData> round3LocalData = nullptr;

    std::unique_ptr<Signature> signature = nullptr;

    GroupParams& params;
    size_t id;
    CL_HSMqk::PublicKey pk;
    std::vector<CL_HSMqk::PublicKey> pki_vector;
    std::vector<OpenSSL::ECPoint> Xi_vector;
    OpenSSL::ECPoint X;

    CL_HSMqk::SecretKey ski;
    OpenSSL::BN xi;

    std::set<size_t> S;
    size_t index;
};

#endif //PARTY_H
