#include <iostream>

#include <syslog.h>
#include <unistd.h>

#include "core.h"

int main(int argc, char **argv)
{
    openlog("wg-autodns", LOG_PERROR, LOG_DAEMON);

    const char *peer_pubkey_b64 = "7wPZD1C9uVV4LSutzPdg6Egxp+F9b7Wdl/edki0VXgs=";
    wg_key peer_pubkey;

    if (wg_key_from_base64(peer_pubkey, peer_pubkey_b64) < 0) {
        perror("Invalid public key");
    }
    std::vector<sockaddr_storage> addrs;
    int rc = resolve_dns("mirrors.ustc.edu.cn", addrs);

    for (const auto &addr : addrs) {
        char str[INET6_ADDRSTRLEN];
        std::cout << inet_ntop(addr.ss_family, &reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr, str, INET6_ADDRSTRLEN)
                  << std::endl;
    }

    rc = update_peer_ip("wgdns", &peer_pubkey, addrs, 22222);

    return 0;
}
