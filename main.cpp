#include <sstream>
#include <iostream>
#include <chrono>

#include "bicycl.hpp"

#include "Utils.h"
#include "Protocol.h"

using namespace BICYCL;

int main()
{
    RandGen randgen;
    size_t n = 5;
    size_t t = 3;

    GroupParams params(SecLevel::_128, n, t, randgen); // n=5, t=3

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