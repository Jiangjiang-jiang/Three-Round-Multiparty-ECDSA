//
// Created by qsang on 24-10-12.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "Party.h"
#include "Utils.h"

class Protocol
{
public:
    explicit Protocol(GroupParams& params);
    void dkg();
    void run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message, std::vector<Signature*>& data_set_for_offline);
    bool verify(const std::vector<Signature*>& ecdsa_sig, const std::vector<unsigned char>& message) const;
    GroupParams& params;
    OpenSSL::ECPoint sig_public_key;
    std::vector<Party> S;
    size_t communication = 0;
};

#endif //PROTOCOL_H
