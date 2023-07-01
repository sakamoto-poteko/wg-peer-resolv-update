cmake_minimum_required(VERSION 3.4)
project(wg-peer-resolv-update)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(wg-peer-resolv-update
        main.cpp
        core.cpp
        core.h
        wireguard.c
        wireguard.h
)
target_link_libraries(wg-peer-resolv-update PRIVATE Threads::Threads)
