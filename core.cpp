#include <cerrno>
#include <cstring>

#include <netdb.h>
#include <syslog.h>
#include <unistd.h>

#include "core.h"

bool is_addr_same(const sockaddr *a, const sockaddr *b)
{
    switch (a->sa_family) {
    case AF_INET:
        return b->sa_family == AF_INET && !std::memcmp(&reinterpret_cast<const sockaddr_in *>(a)->sin_addr, &reinterpret_cast<const sockaddr_in *>(b)->sin_addr, sizeof(in_addr));
    case AF_INET6:
        return b->sa_family == AF_INET6 && !std::memcmp(&reinterpret_cast<const sockaddr_in6 *>(a)->sin6_addr, &reinterpret_cast<const sockaddr_in6 *>(b)->sin6_addr, sizeof(in6_addr));
    default:
        return false;
    }
}

int update_peer_ip(const char *if_name, const wg_key *peer_pubkey,
    const std::vector<sockaddr_storage> &addresses)
{
    // get peer addr
    // cond 1: if peer addr matches any addr in addresses, no op
    // cond 2: if no peer addr matches but addresses not empty, use the first one in addresses
    // cond 3: if no peer addr matches and addresses empty, no op

    if (addresses.empty()) {
        // cond 3
        return 0;
    }

    wg_device *device;
    if (wg_get_device(&device, if_name) < 0) {
        syslog(LOG_DEBUG, "wireguard device %s is not found", if_name);
        return -ENOENT;
    }

    int rc = 0;
    wg_peer *peer;
    wg_for_each_peer(device, peer)
    {
        if (std::memcmp(peer->public_key, peer_pubkey, sizeof(wg_key)) == 0) {
            // pub key match, this is the peer
            for (const sockaddr_storage &resolved_address : addresses) {
                if (is_addr_same(reinterpret_cast<const sockaddr *>(&resolved_address), &peer->endpoint.addr)) {
                    // cond 1
                    goto update_peer_cleanup;
                }
            }

            // no matched ip?
            // set to first
            // if existing endpoint is v4, use first v4 in addr
            // if existing endpoint is v6, use first v6 in addr
            // if no existing endpoint, use first v4
        }
    }

update_peer_cleanup:
    wg_free_device(device);
    return rc;
}

int resolve_dns(const char *peer_dns, std::vector<sockaddr_storage> &addresses)
{
    addrinfo hints = { 0 };

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
        sockaddr_storage addr = { 0 };
        switch (rp->ai_family) {
        case AF_INET:
            std::memcpy(&addr, rp->ai_addr, sizeof(sockaddr_in));
            break;
        case AF_INET6:
            std::memcpy(&addr, rp->ai_addr, sizeof(sockaddr_in6));
            break;
        default:
            syslog(LOG_CRIT, "Invalid socket type: %d", rp->ai_family);
            rc = -EPFNOSUPPORT;
            goto resolve_dns_cleanup;
        }
        addresses.push_back(addr);
    }

resolve_dns_cleanup:
    freeaddrinfo(result);
    return rc;
}
