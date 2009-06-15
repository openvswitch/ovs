/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/watchdog.h>


/* Default values for the interval and timer.  In seconds. */
#define DEFAULT_INTERVAL  1
#define DEFAULT_TIMEOUT   30

int fd = -1;

/* The WDT is automatically enabled when /dev/watchdog is opened.  If we
 * do not send the magic value to the device first before exiting, the 
 * system will reboot.  This function allows the program to exit without 
 * causing a reboot.
 */
static void
cleanup(void)
{
    if (fd == -1) {
        return;
    }

    /* Writing the magic value "V" to the device is an indication that
     * the device is about to be closed.  This causes the watchdog to be
     * disabled after the call to close.
     */
    if (write(fd, "V", 1) != 1) {
        fprintf(stderr, "Couldn't write magic val: %d\n", errno);
        return;
    }
    close(fd); 
    fd = -1;
}


/* If we receive a SIGINT, cleanup first, which will disable the
 * watchdog timer.
 */
static void
sighandler(int signum)
{
    cleanup();
    signal(signum, SIG_DFL);
    raise(signum);
}

static void
setup_signal(void)
{
    struct sigaction action;

    action.sa_handler = sighandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(SIGINT, &action, NULL) != 0) {
        fprintf(stderr, "Problem setting up SIGINT handler...\n");
    }
    if (sigaction(SIGTERM, &action, NULL) != 0) {
        fprintf(stderr, "Problem setting up SIGTERM handler...\n");
    }
}


/* Print information on the WDT hardware */
static void
print_wdt_info(void)
{
    struct watchdog_info ident;

    if (ioctl(fd, WDIOC_GETSUPPORT, &ident) == -1) {
        fprintf(stderr, "Couldn't get version: %d\n", errno);
        cleanup();
        exit(-1);
    }
    printf("identity: %s, ver: %d, opt: %#x\n", ident.identity, 
            ident.firmware_version, ident.options);
}


static void
print_help(char *progname)
{
    printf("%s: Watchdog timer utility\n", progname);
    printf("usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -t, --timeout=SECS     expiration time of WDT (default: %d)\n",
            DEFAULT_TIMEOUT);
    printf("  -i, --interval=SECS    interval to send keep-alives (default: %d)\n",
            DEFAULT_INTERVAL);
    printf("  -d, --disable          disable the WDT and exit\n");
    printf("  -h, --help             display this help message\n");
    printf("  -v, --verbose          enable verbose printing\n");
    printf("  -V, --version          display version information of WDT and exit\n");
}


int main(int argc, char *argv[])
{
    int arg;
    int optc;
    int verbose = 0;
    int interval = DEFAULT_INTERVAL;
    int timeout = DEFAULT_TIMEOUT;
    static struct option const longopts[] =
    { 
        {"timeout", required_argument, NULL, 't'},
        {"interval", required_argument, NULL, 'i'},
        {"disable", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},
        {0, 0, 0, 0}
    };

    setup_signal();

    fd = open("/dev/watchdog", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Couldn't open watchdog device: %s\n", strerror(errno));
        exit(-1);
    }

    while ((optc = getopt_long(argc, argv, "t:i:dh?vV", longopts, NULL)) != -1) {
        switch (optc) {
        case 't':
            timeout = strtol(optarg, NULL, 10);
            if (!timeout) {
                fprintf(stderr, "Invalid timeout: %s\n", optarg);
                goto error;
            }
            break;

       case 'i':
            interval = strtol(optarg, NULL, 10);
            if (!interval) {
                fprintf(stderr, "Invalid interval: %s\n", optarg);
                goto error;
            }
            break;

        case 'd':
            arg = WDIOS_DISABLECARD;
            if (ioctl(fd, WDIOC_SETOPTIONS, &arg) == -1) {
                fprintf(stderr, "Couldn't disable: %d\n", errno);
                goto error;
            }
            cleanup();
            exit(0);
            break;

        case 'h':
            print_help(argv[0]);
            cleanup();
            exit(0);
            break;

        case 'v':
            verbose = 1;
            break;

        case 'V':
            print_wdt_info();
            cleanup();
            exit(0);
            break;

        default:
            print_help(argv[0]);
            goto error;
            break;
        }
    }

    argc -= optind;
    argv += optind;

    /* Sanity-check the arguments */
    if (argc != 0) {
        fprintf(stderr, "Illegal argument: %s\n", argv[0]);
        goto error;
    }

    if (verbose) {
        print_wdt_info();
        printf("timeout: %d, interval: %d\n", timeout, interval);
    }

    /* Prevent the interval being greater than the timeout, since it
     * will always cause a reboot.
     */
    if (interval > timeout) {
        fprintf(stderr, "Interval greater than timeout: %d > %d\n", 
                interval, timeout);
        goto error;
    }

    /* Always set the timeout */
    if (ioctl(fd, WDIOC_SETTIMEOUT, &timeout) == -1) {
        fprintf(stderr, "Couldn't set timeout: %d\n", errno);
        goto error;
    }

    /* Loop and send a keep-alive every "interval" seconds */
    while (1) {
        if (verbose) {
            if (ioctl(fd, WDIOC_GETTIMELEFT, &arg) == -1) {
                fprintf(stderr, "Couldn't get time left: %d\n", errno);
                goto error;
            }
            printf("Sending keep alive, time remaining: %d\n", arg);
        }

        /* Send a keep-alive.  The argument is ignored */
        if (ioctl(fd, WDIOC_KEEPALIVE, &arg) == -1) {
            fprintf(stderr, "Couldn't keepalive: %d\n", errno);
            goto error;
        }

        sleep(interval);
    }

    /* Never directly reached... */
error:
    cleanup();
    exit(-1);
}
