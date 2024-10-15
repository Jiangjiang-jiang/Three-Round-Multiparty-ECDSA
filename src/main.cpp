#include <sstream>
#include <iostream>
#include <chrono>

#include "../include/Protocol.h"

using namespace BICYCL;

int main()
{
    RandGen rng;
    size_t n = 20;
    size_t t = 19;

    GroupParams params(SecLevel::_128, n, t, rng);

    Protocol protocol(params);
    protocol.dkg();

    std::set<size_t> party_set = select_parties(rng, n, t);
    std::vector<unsigned char> message;
    randomize_message(message);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<Signature> signature_set = protocol.run(party_set, message);
    auto end = std::chrono::high_resolution_clock::now();

    bool ret = protocol.verify(signature_set, message);
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