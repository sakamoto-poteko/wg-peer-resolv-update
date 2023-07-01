#include <csignal>
#include <cstring>
#include <iostream>

#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include "core.h"

void print_version()
{
    std::fprintf(stderr, "VERSION PLACEHOLDER\n");
}

void parse_args(int argc, char **argv, ResolvUpdateConfig &config)
{
    bool device_set = false;
    bool pubkey_set = false;
    bool host_set = false;
    bool port_set = false;
    unsigned long interval = 0;
    unsigned long port = 0;

    int c;
    char *int_end_ptr = nullptr;

    wg_key peer_pubkey;
    static struct option long_options[] = {
        { "device", required_argument, nullptr, 'd' },
        { "pubkey", required_argument, nullptr, 'k' },
        { "host", required_argument, nullptr, 'h' },
        { "port", required_argument, nullptr, 'p' },
        { "interval", required_argument, nullptr, 'i' },
        { "prefer-ipv4", no_argument, nullptr, '4' },
        { "prefer-ipv6", no_argument, nullptr, '6' },
        { "debug", no_argument, nullptr, 'D' },
        { "frontend", no_argument, nullptr, 'f' },
        { "version", no_argument, nullptr, 'V' },
        { 0, 0, 0, 0 }
    };

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "Vd:k:h:p:i:46Df", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'V':
            print_version();
            exit(EXIT_SUCCESS);
            break;

        case 'd':
            config.wg_device_name = std::string(optarg);
            device_set = true;
            break;

        case 'k':
            if (wg_key_from_base64(peer_pubkey, optarg) < 0) {
                std::perror("Invalid peer public key");
                exit(EXIT_FAILURE);
            }
            std::memcpy(config.wg_peer_pubkey, peer_pubkey, sizeof(wg_key));
            config.wg_peer_pubkey_base64 = std::string(optarg);
            pubkey_set = true;
            break;

        case 'h':
            config.peer_hostname = std::string(optarg);
            host_set = true;
            break;

        case 'p':
            port = std::strtoul(optarg, &int_end_ptr, 10);
            if (*int_end_ptr != '\0' || port > 65535) {
                std::fprintf(stderr, "%s is not a valid port\n", optarg);
                exit(EXIT_FAILURE);
            }
            config.peer_port = port;
            port_set = true;
            break;

        case 'i':
            interval = std::strtoul(optarg, &int_end_ptr, 10);
            if (*int_end_ptr != '\0') {
                std::fprintf(stderr, "%s is not a valid interval\n", optarg);
                exit(EXIT_FAILURE);
            }
            config.refresh_interval_ms = interval;
            break;

        case '4':
            config.prefer_ipv4 = true;
            break;

        case '6':
            if (config.prefer_ipv4) {
                fprintf(stderr, "Can't prefer both v4 and v6\n");
                exit(EXIT_FAILURE);
            }
            config.prefer_ipv4 = false;
            break;

        case 'v':
            config.debug = true;
            break;

        case 'f':
            config.frontend = true;
            break;

        case '?':
            // unknown option
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
            break;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "excess argument%s: ", argc - optind > 1 ? "s" : "");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
    }

    if (!device_set) {
        fprintf(stderr, "wireguard device is required\n");
        exit(EXIT_FAILURE);
    }

    if (!pubkey_set) {
        fprintf(stderr, "wireguard peer public key is required\n");
        exit(EXIT_FAILURE);
    }

    if (!host_set) {
        fprintf(stderr, "peer hostname is required\n");
        exit(EXIT_FAILURE);
    }

    if (!port_set) {
        fprintf(stderr, "port is required\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    std::signal(SIGINT, sigint_handler);

    ResolvUpdateConfig config = {
        .prefer_ipv4 = true,
        .refresh_interval_ms = 1000,
    };

    parse_args(argc, argv, config);
    int rc = 0;
    if (config.frontend) {
        openlog(argv[0], LOG_PERROR, LOG_USER);
        syslog(LOG_INFO, "Running in frontend\n");
    } else {
        openlog(argv[0], 0, LOG_DAEMON);
        rc = daemon(0, 0);
        if (rc != 0) {
            syslog(LOG_CRIT, "Daemonize failed: %s", std::strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (config.debug) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
        setlogmask(LOG_UPTO(LOG_INFO));
    }

    task_resolve_and_update(config);

    return 0;
}
