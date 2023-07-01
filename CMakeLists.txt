cmake_minimum_required(VERSION 3.4)
project(wg-peer-resolv-update)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)

add_executable(wg-peer-resolv-update
        main.cpp
        core.cpp
        core.h
        wireguard.c
        wireguard.h
)
