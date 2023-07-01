#ifndef CORE_H
#define CORE_H

#include <cstdint>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "wireguard.h"

struct ResolvUpdateConfig {
    std::string wg_device_name;
    std::string wg_peer_pubkey_base64;
    wg_key wg_peer_pubkey;
    std::string peer_hostname;
    std::uint16_t peer_port;
    bool prefer_ipv4;
    std::uint64_t refresh_interval_ms;
    bool verbose;
    bool frontend;
};

void task_resolve_and_update(const ResolvUpdateConfig &config);
void sigint_handler(int);

#endif