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

const sockaddr *get_first_address(bool prefer_v4, const std::vector<sockaddr_storage> &addresses)
{
    if (addresses.empty()) {
        return nullptr;
    }

    for (const sockaddr_storage &addr : addresses) {
        if (addr.ss_family == prefer_v4 ? AF_INET : AF_INET6) {
            return reinterpret_cast<const sockaddr *>(&addr);
        }
    }
    return reinterpret_cast<const sockaddr *>(&addresses.at(0));
}

// if the port of the peer is already set, the port param has no use
int update_peer_ip(const char *if_name, const wg_key *peer_pubkey,
    const std::vector<sockaddr_storage> &addresses, std::uint16_t port)
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

            const sockaddr *target = nullptr;
            switch (peer->endpoint.addr.sa_family) {
            // if no existing endpoint, use first v4, then v6
            // if existing endpoint is v4, use first v4, then v6
            case AF_UNSPEC:
            case AF_INET:
                target = get_first_address(true, addresses);
                break;
            // if existing endpoint is v6, use first v6, then v4
            case AF_INET6:
                target = get_first_address(false, addresses);
                break;
            default:
                syslog(LOG_CRIT, "unexpected protocol type: %d. report this bug: " __FILE__ ":%d", peer->endpoint.addr.sa_family, __LINE__);
                rc = -EPROTONOSUPPORT;
                goto update_peer_cleanup;
            }

            // target is not supposed to be nullptr
            // the only way to make it null is to pass empty addr list, but addr list won't be empty here

            char original_ip[INET6_ADDRSTRLEN];
            char new_ip[INET6_ADDRSTRLEN];
            const char *ori_ip_ok = inet_ntop(peer->endpoint.addr.sa_family, &reinterpret_cast<const sockaddr_in *>(&peer->endpoint.addr)->sin_addr, original_ip, INET6_ADDRSTRLEN);
            const char *new_ip_ok = inet_ntop(target->sa_family, &reinterpret_cast<const sockaddr_in *>(target)->sin_addr, new_ip, INET6_ADDRSTRLEN);

            syslog(LOG_INFO, "peer of wg %s, original ip %s, new ip %s", if_name, ori_ip_ok ? original_ip : "(N/A)", new_ip_ok ? new_ip : "(N/A)");

            switch (target->sa_family) {
            case AF_INET:
                std::memcpy(&peer->endpoint.addr4, target, sizeof(sockaddr_in));
                peer->endpoint.addr4.sin_port = htons(port);
                break;
            case AF_INET6:
                std::memcpy(&peer->endpoint.addr6, target, sizeof(sockaddr_in6));
                peer->endpoint.addr6.sin6_port = htons(port);
                break;
            default:
                syslog(LOG_CRIT, "Invalid socket type: %d", target->sa_family);
                rc = -EPFNOSUPPORT;
                goto update_peer_cleanup;
            }

            rc = wg_set_device(device);
            if (rc < 0) {
                syslog(LOG_ERR, "set wireguard peer failed: %s", std::strerror(-rc));
                goto update_peer_cleanup;
            }
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
