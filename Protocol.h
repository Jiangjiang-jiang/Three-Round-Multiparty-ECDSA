//
// Created by qsang on 24-10-12.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "Utils.h"
#include "Party.h"

class Protocol
{
public:
    explicit Protocol(GroupParams& params);
    void dkg();
    bool run();
    std::set<size_t> select_parties(RandGen& rng, size_t n, size_t t);
    std::vector<Party> S;
    GroupParams& params;
};

#endif //PROTOCOL_H
