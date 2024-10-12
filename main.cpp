#include <numeric>
#include <string>
#include <sstream>
#include <iostream>

#include <memory>
#include <set>
#include <unordered_map>
#include <vector>
#include <stdexcept>

#include "bicycl.hpp"
using namespace std;
using namespace BICYCL;
using Commitment = OpenSSL::HashAlgo::Digest;
using CommitmentSecret = std::vector<unsigned char>;
#include "Utils.h"
#include "Party.h"
#include "Protocol.h"


int main()
{
    RandGen randgen;
    unsigned int n = 5;
    unsigned int t = 3;
    GroupParams params(SecLevel::_128, n, t, randgen);

    Protocol protocol(params);
    protocol.dkg();
    bool ret = protocol.run();
    if (ret)
    {
        cout << "run success" << endl;
    }
    else
    {
        cout << "run fail" << endl;
    }
    return 0;
}