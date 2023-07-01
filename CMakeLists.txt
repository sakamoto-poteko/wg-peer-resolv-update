cmake_minimum_required(VERSION 3.4)
project(wg-peer-resolv-update)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED YES)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(PRE_CONFIGURE_FILE "version/git.c.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/git.c")
include(cmake/git_watcher.cmake)

add_executable(${PROJECT_NAME}
        main.cpp
        core.cpp
        core.h
        wireguard.c
        wireguard.h
        ${POST_CONFIGURE_FILE}
)
add_dependencies(${PROJECT_NAME} check_git)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
