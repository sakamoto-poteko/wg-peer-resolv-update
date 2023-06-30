#ifndef CORE_H
#define CORE_H

#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "wireguard.h"

int update_peer_ip(const char *if_name, const wg_key *peer_pubkey,
    const std::vector<sockaddr_storage> &addresses);

int resolve_dns(const char *peer_dns, std::vector<sockaddr_storage> &addresses);

#endif