cmake_minimum_required(VERSION 3.24)
project(wg-peer-resolv-update)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

add_executable(wg-peer-resolv-update
        main.cpp
#        wireguard.c
#        wireguard.h
#        wireguard.hpp
        )
