/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stddef.h>
#include <unistd.h>

#include "command-line.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

#define DEFAULT_PORT 6630

#define MAX_SOCKETS 65535
static int n_batches = 1;
static int n_sockets = 100;

static struct in_addr local_addr;
static unsigned short int local_min_port, local_max_port;

static struct in_addr remote_addr;
static unsigned short int remote_min_port, remote_max_port;

static double max_rate;

static double timeout;

static const struct command all_commands[];

static void parse_options(int argc, char *argv[]);
static void usage(void);

static long long int
time_in_msec(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0) {
        ovs_fatal(errno, "gettimeofday");
    }

    return tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_FACILITY, VLL_EMER);
    parse_options(argc, argv);
    run_command(argc - optind, argv + optind, all_commands);
    return 0;
}

static void
parse_target(const char *s_, struct in_addr *addr,
             unsigned short int *min, unsigned short int *max)
{
    char *s = xstrdup(s_);
    char *colon;
    int error;

    colon = strchr(s, ':');
    if (colon) {
        *colon = '\0';
    }

    if (*s != '\0') {
        error = lookup_hostname(s, addr);
        if (error) {
            ovs_fatal(error, "failed to look up IP address for \"%s\"", s_);
        }
    } else {
        addr->s_addr = htonl(INADDR_ANY);
    }

    *min = *max = 0;
    if (colon && colon[1] != '\0') {
        const char *ports = colon + 1;
        if (sscanf(ports, "%hu-%hu", min, max) == 2) {
            if (*min > *max) {
                ovs_fatal(0, "%s: minimum is greater than maximum", s_);
            }
        } else if (sscanf(ports, "%hu", min) == 1) {
            *max = *min;
        } else {
            ovs_fatal(0, "%s: number or range expected", s_);
        }
    }

    free(s);
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"local", required_argument, NULL, 'l'},
        {"remote", required_argument, NULL, 'r'},
        {"batches", required_argument, NULL, 'b'},
        {"sockets", required_argument, NULL, 's'},
        {"max-rate", required_argument, NULL, 'c'},
        {"timeout", required_argument, NULL, 'T'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    local_addr.s_addr = htonl(INADDR_ANY);
    local_min_port = local_max_port = 0;

    remote_addr.s_addr = htonl(0);
    remote_min_port = remote_max_port = 0;

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l':
            parse_target(optarg,
                         &local_addr, &local_min_port, &local_max_port);
            break;

        case 'r':
            parse_target(optarg,
                         &remote_addr, &remote_min_port, &remote_max_port);
            if (remote_addr.s_addr == htonl(INADDR_ANY)) {
                ovs_fatal(0, "remote IP address is required");
            }
            break;

        case 'b':
            n_batches = atoi(optarg);
            if (n_batches < 0) {
                ovs_fatal(0, "--batches or -b argument must be at least 1");
            }
            break;

        case 's':
            n_sockets = atoi(optarg);
            if (n_sockets < 1 || n_sockets > MAX_SOCKETS) {
                ovs_fatal(0, "--sockets or -s argument must be between 1 "
                          "and %d (inclusive)", MAX_SOCKETS);
            }
            break;

        case 'c':
            max_rate = atof(optarg);
            if (max_rate <= 0.0) {
                ovs_fatal(0, "--max-rate or -c argument must be positive");
            }
            break;

        case 'T':
            timeout = atoi(optarg);
            if (!timeout) {
                ovs_fatal(0, "-T or --timeout argument must be positive");
            }
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("\
%s: Open vSwitch flow setup benchmark utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
  latency                     connect many times all at once\n\
  rate                        measure sustained flow setup rate\n\
  listen                      accept TCP connections\n\
  help                        display this help message\n\
\n\
Command options:\n\
  -l, --local [IP][:PORTS]    use local IP and range of PORTS\n\
  -r, --remote IP[:PORTS]     connect to remote IP and PORTS\n\
  -s, --sockets N             number of sockets for \"rate\" or \"latency\"\n\
  -b, --batches N             number of connection batches for \"latency\"\n\
  -c, --max-rate NPERSEC      connection rate limit for \"rate\"\n\
  -T, --timeout MAXSECS       max number of seconds to run for \"rate\"\n\
\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
cmd_listen(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct pollfd *fds;
    int n_fds;
    int port;
    int i;

    if (!local_min_port && !local_max_port) {
        local_min_port = local_max_port = DEFAULT_PORT;
    }
    fds = xmalloc((1 + local_max_port - local_min_port) * sizeof *fds);
    n_fds = 0;
    for (port = local_min_port; port <= local_max_port; port++) {
        struct sockaddr_in sin;
        unsigned int yes = 1;
        int error;
        int fd;

        /* Create socket, set SO_REUSEADDR. */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            ovs_fatal(errno, "failed to create socket");
        }
        error = set_nonblocking(fd);
        if (error) {
            ovs_fatal(error, "failed to set non-blocking mode");
        }
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
            ovs_fatal(errno, "setsockopt(SO_REUSEADDR) failed");
        }

        /* Bind. */
        sin.sin_family = AF_INET;
        sin.sin_addr = remote_addr;
        sin.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *) &sin, sizeof sin) < 0) {
            ovs_fatal(errno, "bind failed");
        }

        /* Listen. */
        if (listen(fd, 10000) < 0) {
            ovs_fatal(errno, "listen failed");
        }

        fds[n_fds].fd = fd;
        fds[n_fds].events = POLLIN;
        n_fds++;
    }

    for (;;) {
        int retval;

        do {
            retval = poll(fds, n_fds, -1);
        } while (retval < 0 && errno == EINTR);
        if (retval < 0) {
            ovs_fatal(errno, "poll failed");
        }

        for (i = 0; i < n_fds; i++) {
            if (fds[i].revents & POLLIN) {
                int newfd;

                do {
                    newfd = accept(fds[i].fd, NULL, NULL);
                } while (newfd < 0 && errno == EINTR);

                if (newfd >= 0) {
                    close(newfd);
                } else if (errno != EAGAIN) {
                    ovs_fatal(errno, "accept failed");
                }
            }
        }
    }
}

/* Increments '*value' within the range 'min...max' inclusive.  Returns true
 * if '*value' wraps around to 'min', otherwise false. */
static bool
increment(unsigned short int *value,
          unsigned short int min, unsigned short int max)
{
    if (*value < max) {
        ++*value;
        return false;
    } else {
        *value = min;
        return true;
    }
}

static void
next_ports(unsigned short int *local_port, unsigned short int *remote_port)
{
    if (increment(local_port, local_min_port, local_max_port)) {
        increment(remote_port, remote_min_port, remote_max_port);
    }
}

static void
bind_local_port(int fd, unsigned short int *local_port,
                unsigned short int *remote_port)
{
    int error;

    if (!local_min_port && !local_max_port) {
        next_ports(local_port, remote_port);
        return;
    }

    do {
        struct sockaddr_in local;

        memset(&local, 0, sizeof local);
        local.sin_family = AF_INET;
        local.sin_addr = local_addr;
        local.sin_port = htons(*local_port);
        error = (bind(fd, (struct sockaddr *) &local, sizeof local) < 0
                 ? errno : 0);
        next_ports(local_port, remote_port);
    } while (error == EADDRINUSE || error == EINTR);
    if (error) {
        ovs_fatal(error, "bind failed");
    }
}

static void
cmd_rate(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned short int local_port;
    unsigned short int remote_port;
    unsigned int completed = 0;
    unsigned int failures = 0;
    long long int start, prev;
    struct pollfd *fds;
    int n_fds;

    if (!remote_addr.s_addr) {
        ovs_fatal(0, "remote address must be specified with -r or --remote");
    }
    if (!remote_min_port && !remote_max_port) {
        remote_min_port = remote_max_port = DEFAULT_PORT;
    }

    local_port = local_min_port;
    remote_port = remote_min_port;
    fds = xmalloc(n_sockets * sizeof *fds);
    n_fds = 0;
    start = prev = time_in_msec();
    for (;;) {
        long long int now;
        long long int may_open;
        int delay;
        int error;
        int j;

        if (max_rate > 0) {
            long long int cur_total = completed + n_fds;
            long long int max_total = (time_in_msec() - start) * (max_rate / 1000.0);
            if (max_total > cur_total) {
                may_open = MIN(n_sockets, max_total - cur_total);
            } else {
                may_open = 0;
            }
            delay = 1000.0 / max_rate;
        } else {
            may_open = n_sockets;
            delay = 1000;
        }

        while (may_open-- > 0 && n_fds < n_sockets) {
            struct sockaddr_in remote;
            int error;
            int fd;

            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                ovs_fatal(errno, "socket failed");
            }

            error = set_nonblocking(fd);
            if (error) {
                ovs_fatal(error, "set_nonblocking failed");
            }

            bind_local_port(fd, &local_port, &remote_port);

            memset(&remote, 0, sizeof remote);
            remote.sin_family = AF_INET;
            remote.sin_addr = remote_addr;
            remote.sin_port = htons(remote_port);
            if (connect(fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
                if (errno == EINPROGRESS) {
                    fds[n_fds].fd = fd;
                    fds[n_fds].events = POLLOUT;
                    fds[n_fds].revents = 0;
                    n_fds++;
                } else if (errno != ECONNREFUSED) {
                    ovs_fatal(errno, "connect");
                }
            } else {
                /* Success, I guess. */
                shutdown(fd, 2);
                close(fd);
                completed++;
            }
        }

        if (n_fds == n_sockets) {
            delay = 1000;
        }

        do {
            error = poll(fds, n_fds, delay) < 0 ? errno : 0;
        } while (error == EINTR);
        if (error) {
            ovs_fatal(errno, "poll");
        }

        for (j = 0; j < n_fds; ) {
            if (fds[j].revents) {
                if (fds[j].revents & POLLERR) {
                    failures++;
                }
                shutdown(fds[j].fd, 2);
                close(fds[j].fd);
                fds[j] = fds[--n_fds];
                completed++;
            } else {
                j++;
            }
        }

        now = time_in_msec();
        if (now >= prev + 1000) {
            long long int elapsed = now - start;
            printf("%.3f s elapsed, %u OK, %u failed, avg %.1f/s\n",
                   elapsed / 1000.0, completed - failures, failures,
                   completed / (elapsed / 1000.0));
            prev = now;

            if (timeout && elapsed > timeout * 1000LL) {
                break;
            }
        }
    }
}

static void
timer_end(long long int start, bool error,
          int *min, int *max, unsigned long long int *total)
{
    int elapsed = time_in_msec() - start;
    static int last_elapsed = INT_MIN;
    char c = error ? '!' : '.';

    if (last_elapsed != elapsed) {
        if (last_elapsed != INT_MIN) {
            putchar('\n');
        }
        printf("%5d %c", elapsed, c);
        fflush(stdout);
        last_elapsed = elapsed;
    } else {
        putchar(c);
        fflush(stdout);
    }

    if (elapsed < *min) {
        *min = elapsed;
    }
    if (elapsed > *max) {
        *max = elapsed;
    }
    *total += elapsed;
}

static void
cmd_latency(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    unsigned short int local_port;
    unsigned short int remote_port;
    int min = INT_MAX;
    int max = 0;
    unsigned long long int total = 0;
    int i;

    if (!remote_addr.s_addr) {
        ovs_fatal(0, "remote address must be specified with -r or --rate");
    }
    if (!remote_min_port && !remote_max_port) {
        remote_min_port = remote_max_port = DEFAULT_PORT;
    }

    local_port = local_min_port;
    remote_port = remote_min_port;
    for (i = 0; i < n_batches; i++) {
        struct pollfd fds[MAX_SOCKETS];
        long long int start;
        int n_fds;
        int j;

        start = time_in_msec();
        n_fds = 0;
        for (j = 0; j < n_sockets; j++) {
            struct sockaddr_in remote;
            int error;
            int fd;

            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                ovs_fatal(errno, "socket failed");
            }

            error = set_nonblocking(fd);
            if (error) {
                ovs_fatal(error, "set_nonblocking failed");
            }

            bind_local_port(fd, &local_port, &remote_port);

            memset(&remote, 0, sizeof remote);
            remote.sin_family = AF_INET;
            remote.sin_addr = remote_addr;
            remote.sin_port = htons(remote_port);
            if (connect(fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
                if (errno == EINPROGRESS) {
                    fds[n_fds].fd = fd;
                    fds[n_fds].events = POLLOUT;
                    fds[n_fds].revents = 0;
                    n_fds++;
                } else if (errno != ECONNREFUSED) {
                    ovs_fatal(errno, "connect");
                }
            } else {
                /* Success, I guess. */
                close(fd);
                timer_end(start, 0, &min, &max, &total);
            }
        }

        while (n_fds > 0) {
            int error;

            do {
                error = poll(fds, n_fds, -1) < 0 ? errno : 0;
            } while (error == EINTR);
            if (error) {
                ovs_fatal(errno, "poll");
            }

            for (j = 0; j < n_fds; ) {
                if (fds[j].revents) {
                    timer_end(start,
                              fds[j].revents & (POLLERR|POLLHUP) ? 1 : 0,
                              &min, &max, &total);
                    close(fds[j].fd);
                    fds[j] = fds[--n_fds];
                } else {
                    j++;
                }
            }
        }
        putchar('\n');
    }

    printf("min %d ms, max %d ms, avg %llu ms\n",
           min, max, total / (1ULL * n_sockets * n_batches));
}

static void
cmd_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
}

static const struct command all_commands[] = {
    { "listen", 0, 0, cmd_listen },
    { "rate", 0, 0, cmd_rate },
    { "latency", 0, 0, cmd_latency },
    { "help", 0, 0, cmd_help },
    { NULL, 0, 0, NULL },
};
