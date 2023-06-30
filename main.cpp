#include <iostream>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include "wireguard.hpp"

struct ip_address {
    sa_family_t family;
    union {
        in_addr addr4;
        in6_addr addr6;
    };
};


int get_peer_ip(const char *if_name, const wg_key *peer_pubkey, ip_address &peer_address) {
    wg_device *device;
    wg_peer *peer;
    int rc = -ENOENT;

    if (wg_get_device(&device, if_name) < 0) {
        syslog(LOG_DEBUG, "wireguard device %s is not found", if_name);
    }

    wg_for_each_peer(device, peer) {
        if (std::memcmp(peer->public_key, peer_pubkey, sizeof(wg_key)) == 0) {
            // pub key match, this is the peer
            sa_family_t family = peer->endpoint.addr.sa_family;
            switch (family) {
                case AF_INET:
                    peer_address.addr4 = peer->endpoint.addr4.sin_addr;
                    break;
                case AF_INET6:
                    peer_address.addr6 = peer->endpoint.addr6.sin6_addr;
                    break;
                default:
                    syslog(LOG_CRIT, "Invalid socket type: %d", family);
                    return -EPFNOSUPPORT;
            }
            peer_address.family = family;
            rc = 0;
            break;
        }
    }

    wg_free_device(device);
    return rc;
}

int resolve_dns(const char *peer_dns, std::vector<ip_address> &addresses) {
    addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED;
    hints.ai_protocol = 0;

    addrinfo *result;
    int rc = getaddrinfo(peer_dns, nullptr, &hints, &result);
    if (rc != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(rc));
        return -255;
    }

    for (const addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        ip_address addr = {0};
        addr.family = rp->ai_family;
        switch (rp->ai_family) {
            case AF_INET:
                addr.addr4 = reinterpret_cast<sockaddr_in *>( rp->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                addr.addr6 = reinterpret_cast<sockaddr_in6 *>(rp->ai_addr)->sin6_addr;
                break;
            default:
                syslog(LOG_CRIT, "Invalid socket type: %d", rp->ai_family);
                return -EPFNOSUPPORT;
        }
        addresses.push_back(addr);
    }
    freeaddrinfo(result);
    return 0;
}

int main(int argc, char **argv) {
    const char *peer_pubkey_b64;
    wg_key peer_pubkey;

    if (wg_key_from_base64(peer_pubkey, peer_pubkey_b64) < 0) {
        perror("Incorrect public key");
    }
    std::vector<ip_address> addrs;
    int rc = resolve_dns("mirrors.ustc.edu.cn", addrs);

    for (auto &addr : addrs) {
        char str[INET6_ADDRSTRLEN];
        std::cout << inet_ntop(addr.family, &addr.addr4, str, INET6_ADDRSTRLEN) << std::endl;
    }

    return 0;
}
