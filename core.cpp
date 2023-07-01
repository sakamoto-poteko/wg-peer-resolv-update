#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#include <netdb.h>
#include <syslog.h>
#include <unistd.h>

#include "core.h"

static std::mutex wait_lock;
static std::condition_variable wait_cv;
static volatile std::sig_atomic_t sigint_status;

static const sockaddr *get_first_address(bool prefer_v4, const std::vector<sockaddr_storage> &addresses);
static bool is_addr_same(const sockaddr *a, const sockaddr *b);
static bool get_address_str(const sockaddr *addr, std::string &str);
static int update_peer_ip(const std::string &if_name, const wg_key *peer_pubkey,
    const std::vector<sockaddr_storage> &addresses, std::uint16_t port);
static int resolve_dns(const std::string &peer_dns, std::vector<sockaddr_storage> &addresses);

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

bool get_address_str(const sockaddr *addr, std::string &str)
{
    char buf[INET6_ADDRSTRLEN];
    const void *addrptr;
    switch (addr->sa_family) {
    case AF_INET:
        addrptr = &reinterpret_cast<const sockaddr_in *>(addr)->sin_addr;
        break;
    case AF_INET6:
        addrptr = &reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_addr;
        break;
    default:
        return false;
    }

    const char *ok = inet_ntop(addr->sa_family, addrptr, buf, INET6_ADDRSTRLEN);
    if (ok) {
        str = std::string(buf);
        return true;
    } else {
        return false;
    }
}

// if the port of the peer is already set, the port param has no use
int update_peer_ip(const std::string &if_name, const wg_key *peer_pubkey,
    const std::vector<sockaddr_storage> &addresses, std::uint16_t port)
{
    // get peer addr
    // cond 1: if peer addr matches any addr in addresses, no op
    // cond 2: if no peer addr matches but addresses not empty, use the first one in addresses
    // cond 3: if no peer addr matches and addresses empty, no op

    if (addresses.empty()) {
        syslog(LOG_DEBUG, "Peer ip unchanged - host ip is not found");

        // cond 3
        return 0;
    }

    wg_device *device;
    if (wg_get_device(&device, if_name.c_str()) < 0) {
        syslog(LOG_DEBUG, "Update peer ip failed: WireGuard device %s is not found", if_name.c_str());
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
                    syslog(LOG_DEBUG, "Peer ip unchanged - host ip unchanged");
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
                syslog(LOG_CRIT, "Unexpected protocol type: %d. Report this bug: " __FILE__ ":%d", peer->endpoint.addr.sa_family, __LINE__);
                rc = -EPROTONOSUPPORT;
                goto update_peer_cleanup;
            }

            // target is not supposed to be nullptr
            // the only way to make it null is to pass empty addr list, but addr list won't be empty here

            std::string original_ip;
            std::string new_ip;

            bool orinal_ip_str_ok = get_address_str(&peer->endpoint.addr, original_ip);
            bool new_ip_str_ok = get_address_str(target, new_ip);

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

            syslog(LOG_DEBUG, "Updating WireGuard device %s, original IP %s, new IP %s...", if_name.c_str(), orinal_ip_str_ok ? original_ip.c_str() : "(N/A)", new_ip_str_ok ? new_ip.c_str() : "(N/A)");

            rc = wg_set_device(device);
            if (rc < 0) {
                syslog(LOG_ERR, "set wireguard peer failed: %s", std::strerror(-rc));
                goto update_peer_cleanup;
            }

            syslog(LOG_INFO, "WireGuard device %s: updated peer with new IP %s...", if_name.c_str(), new_ip_str_ok ? new_ip.c_str() : "(N/A)");
        }
    }

update_peer_cleanup:
    wg_free_device(device);
    return rc;
}

/// @brief
/// @param peer_dns
/// @param addresses
/// @return -254 if no host found. -255 other failures.
int resolve_dns(const std::string &peer_dns, std::vector<sockaddr_storage> &addresses)
{
    addrinfo hints = { 0 };

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED;
    hints.ai_protocol = 0;

    addrinfo *result;
    int rc = getaddrinfo(peer_dns.c_str(), nullptr, &hints, &result);
    if (rc == EAI_NODATA || rc == EAI_NONAME) {
        syslog(LOG_DEBUG, "Resolve error: host or ip not found for %s", peer_dns.c_str());
        return -254;
    }

    if (rc != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rc));
        return -255;
    }

    auto sockaddr_storage_cmp = [](const sockaddr_storage &a, const sockaddr_storage &b) { return std::memcmp(&a, &b, sizeof(a)); };
    std::set<sockaddr_storage, decltype(sockaddr_storage_cmp)> addrset(sockaddr_storage_cmp);
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
        addrset.insert(addr);
    }

resolve_dns_cleanup:
    freeaddrinfo(result);
    addresses = std::vector<sockaddr_storage>(addrset.begin(), addrset.end());
    return rc;
}

void task_resolve_and_update(const ResolvUpdateConfig &config)
{
    syslog(LOG_INFO, "Starting resolve and update task...");
    syslog(LOG_INFO, "Target WireGuard device %s, peer key %s, target hostname %s, target port %u",
        config.wg_device_name.c_str(), config.wg_peer_pubkey_base64.c_str(), config.peer_hostname.c_str(), config.peer_port);

    int rc = 0;
    while (true) {
        std::vector<sockaddr_storage> addrs;
        rc = resolve_dns(config.peer_hostname, addrs);
        if (rc == -254) {
            // no host found. don't log.
            goto task_resolve_and_update_loop_end;
        }
        if (rc < 0) {
            syslog(LOG_ERR, "Failed to resolve hostname");
            goto task_resolve_and_update_loop_end;
        }

        if (config.verbose) {
            if (addrs.empty()) {
                syslog(LOG_DEBUG, "No IP found for host %s", config.peer_hostname.c_str());
            } else {
                std::stringstream ss;
                for (const auto &addr : addrs) {
                    std::string str;
                    bool ok = get_address_str(reinterpret_cast<const sockaddr *>(&addr), str);

                    if (ok) {
                        ss << str << " ";
                    } else {
                        ss << "(invalid) ";
                    }
                }
                std::string ips(ss.str());
                syslog(LOG_DEBUG, "%d IP(s) retrieved: %s", addrs.size(), ips.c_str());
            }
        }

        rc = update_peer_ip(config.wg_device_name.c_str(), &config.wg_peer_pubkey, addrs, config.peer_port);
        if (rc < 0) {
            if (rc = -ENOENT) {
                // no such device
            } else {
                syslog(LOG_ERR, "Failed to update peer ip");
            }
            goto task_resolve_and_update_loop_end;
        }
    task_resolve_and_update_loop_end:
        std::unique_lock<std::mutex> lock(wait_lock);
        bool signal_hit = wait_cv.wait_for(lock, std::chrono::milliseconds(config.refresh_interval_ms), [] { return sigint_status; });
        if (signal_hit) {
            // signal
            break;
        }
    }
    syslog(LOG_INFO, "Exiting resolve and update task...");
}

void sigint_handler(int)
{
    syslog(LOG_ERR, "SIGINT received");
    sigint_status = 1;
    wait_cv.notify_all();
}