cmake_minimum_required(VERSION 3.29)
project(Threshold_ECDSA)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(include/bicycl EXCLUDE_FROM_ALL)

find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)

find_package (OpenSSL REQUIRED)
# find_package (benchmark) #Google Benchmark

find_package(OpenSSL REQUIRED)

add_executable(Threshold_ECDSA main.cpp
        Party.cpp
        Party.h
        Utils.cpp
        Utils.h
        Protocol.cpp
        Protocol.h)

target_link_libraries(Threshold_ECDSA
        PRIVATE
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)