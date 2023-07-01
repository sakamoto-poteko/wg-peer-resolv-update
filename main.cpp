#include <csignal>
#include <cstring>
#include <iostream>

#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include "core.h"
#include "version/git.h"

void print_help_short(const char *me)
{
    std::fprintf(stderr,
        "Usage: %s -d wg_device -k peer_pubkey -h hostname -p port [-i interval] [-4] [-6]\n"
        "       [-D] [-f] [-v] [--help]\n",
        me);
}

void print_help_long_and_exit(const char *me)
{
    print_help_short(me);
    std::fprintf(stderr,
        "Periodically checks and updates WireGuard peer endpoint IP against hostname."
        "\n"
        "   -d, --device        the WireGuard device which has the peer whose endpoint is to be updated\n"
        "   -k, --pubkey        the public key of the peer whose endpoint is to be updated\n"
        "   -h, --hostname      the hostname of the peer endpoint, which will be periodically resolved\n"
        "   -p, --port          the port of the endpoint\n"
        "   -i, --interval      the interval between hostname resolution\n"
        "   -4, --prefer-ipv4   prefer IPv4\n"
        "   -6, --prefer-ipv6   prefer IPv6\n"
        "   -D, --debug         Enable debug logging\n"
        "   -f, --frontend      Run in frontend. Do not daemonize\n"
        "   -v, --version       Print the version info\n"
        "   --help              Print this help\n"
        "\n"
        "Report bugs on https://github.com/sakamoto-poteko/wg-peer-resolv-update/issues, or mail to Afa <afa@afa.moe>\n");
    exit(EXIT_SUCCESS);
}

void print_version_and_exit()
{
    std::printf("wg-peer-resolv-update version %s.\n"
                "Copyright (C) 2023, Afa Cheng <afa@afa.moe>\n",
        git_Describe());
    exit(EXIT_SUCCESS);
}

void parse_args(int argc, char **argv, ResolvUpdateConfig &config)
{
    bool device_set = false;
    bool pubkey_set = false;
    bool host_set = false;
    bool port_set = false;
    bool is_prefer_v4_set = false;
    bool is_prefer_v6_set = false;
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
        { "version", no_argument, nullptr, 'v' },
        { "help", no_argument, nullptr, 0 },
        { 0, 0, 0, 0 }
    };

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "vd:k:h:p:i:46Df", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'v':
            print_version_and_exit();
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
            is_prefer_v4_set = true;
            break;

        case '6':
            is_prefer_v6_set = true;
            break;

        case 'D':
            config.debug = true;
            break;

        case 'f':
            config.frontend = true;
            break;

        case 0:
            if (std::strcmp("help", long_options[option_index].name) == 0) {
                print_help_long_and_exit(argv[0]);
            }
        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
        case '?':
            // unknown option
            goto print_help_and_exit_failure;
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
        goto print_help_and_exit_failure;
    }

    if (!pubkey_set) {
        fprintf(stderr, "wireguard peer public key is required\n");
        goto print_help_and_exit_failure;
    }

    if (!host_set) {
        fprintf(stderr, "peer hostname is required\n");
        goto print_help_and_exit_failure;
    }

    if (!port_set) {
        fprintf(stderr, "port is required\n");
        goto print_help_and_exit_failure;
    }

    if (is_prefer_v4_set && is_prefer_v6_set) {
        fprintf(stderr, "Can't prefer both v4 and v6\n");
        exit(EXIT_FAILURE);
    }

    if (is_prefer_v4_set) {
        config.ip_version_preference = IPVersionPreference::PreferV4;
    } else if (is_prefer_v6_set) {
        config.ip_version_preference = IPVersionPreference::PreferV6;
    } else {
        config.ip_version_preference = IPVersionPreference::NoPreference;
    }

    return;

print_help_and_exit_failure:
    print_help_short(argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    std::signal(SIGINT, sigint_handler);

    ResolvUpdateConfig config = {
        .ip_version_preference = IPVersionPreference::NoPreference,
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
