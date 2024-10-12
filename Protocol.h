//
// Created by qsang on 24-10-12.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cmath>
#include <set>
#include "Utils.h"
#include "Party.h"


class Protocol
{
public:
    explicit Protocol(GroupParams& params) : params(params) { }
    void dkg();
    bool run();
    std::vector<Party> S;
    GroupParams& params;
};

#endif //PROTOCOL_H
