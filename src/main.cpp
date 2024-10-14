#include <sstream>
#include <iostream>
#include <chrono>

#include "../include/Protocol.h"

using namespace BICYCL;

int main()
{
    RandGen randgen;
    size_t n = 20;
    size_t t = 19;

    GroupParams params(SecLevel::_128, n, t, randgen);

    Protocol protocol(params);

    protocol.dkg();
    auto start = std::chrono::high_resolution_clock::now();
    bool ret = protocol.run();
    auto end = std::chrono::high_resolution_clock::now();
    if (ret)
    {
        std::chrono::duration<double> duration = end - start;
        std::cout << "run success in " << duration.count() / static_cast<double>(n) << " s" << std::endl;
    }
    else
    {
        std::cout << "run fail" << std::endl;
    }
    return 0;
}