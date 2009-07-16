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


#include <config.h>
#include <assert.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <term.h>
#include <unistd.h>
#include "command-line.h"
#include "extras/ezio/byteq.h"
#include "extras/ezio/tty.h"
#include "extras/ezio/vt.h"
#include "daemon.h"
#include "ezio.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "terminal.h"
#include "timeval.h"
#include "util.h"

#define THIS_MODULE VLM_ezio_term
#include "vlog.h"

/* EZIO button status. */
enum btn_status {
    BTN_UP    = 1 << 0,
    BTN_DOWN  = 1 << 1,
    BTN_ENTER = 1 << 2,
    BTN_ESC   = 1 << 3
};

/* -e, --ezio: EZIO3 serial device file. */
static char *ezio_dev = "/dev/ttyS1";

/* -i, --input: Terminal from which to accept additional keyboard input. */
static char *input_dev = NULL;

struct inputdev;
static int inputdev_open(const char *name, struct inputdev **);
static void inputdev_close(struct inputdev *);
static int inputdev_run(struct inputdev *, struct byteq *);
static void inputdev_update(struct inputdev *, const struct ezio *);
static void inputdev_wait(struct inputdev *);

static struct scanner *scanner_create(void);
static void scanner_destroy(struct scanner *);
static void scanner_run(struct scanner *, struct ezio *);
static void scanner_wait(struct scanner *);
static void scanner_left(struct scanner *, struct ezio *);
static void scanner_right(struct scanner *, struct ezio *);

static struct updater *updater_create(void);
static void updater_destroy(struct updater *);
static int updater_run(struct updater *, const struct ezio *shadow,
                       int ezio_fd);
static void updater_wait(struct updater *, int ezio_fd);
enum btn_status updater_get_buttons(struct updater *);
bool updater_has_buttons(const struct updater *);

static void handle_buttons(struct updater *, struct scanner *,
                           struct byteq *, struct ezio *);

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct terminal *terminal;
    struct updater *updater;
    struct scanner *scanner;
    struct inputdev *inputdev;
    struct byteq inputq;
    struct ezio ezio;
    int ezio_fd, pty_fd, dummy_fd;
    int retval;
    int i;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    argc -= optind;
    argv += optind;

    /* Make sure that the ezio3 terminfo entry is available. */
    dummy_fd = get_null_fd();
    if (dummy_fd >= 0) {
        if (setupterm("ezio3", dummy_fd, &retval) == ERR) {
            if (retval == 0) {
                ovs_fatal(0, "Missing terminfo entry for ezio3.  "
                          "Did you run \"make install\"?");
            } else {
                ovs_fatal(0, "Missing terminfo database.  Is ncurses "
                          "properly installed?");
            }
        }
        del_curterm(cur_term);
    }

    /* Lock serial port. */
    retval = tty_lock(ezio_dev);
    if (retval) {
        ovs_fatal(retval, "%s: lock failed", ezio_dev);
    }

    /* Open EZIO and configure as 2400 bps, N-8-1, in raw mode. */
    ezio_fd = open(ezio_dev, O_RDWR | O_NOCTTY);
    if (ezio_fd < 0) {
        ovs_fatal(errno, "%s: open", ezio_dev);
    }
    retval = tty_set_raw_mode(ezio_fd, B2400);
    if (retval) {
        ovs_fatal(retval, "%s: failed to configure tty parameters", ezio_dev);
    }

    /* Open keyboard device for input. */
    if (input_dev) {
        retval = inputdev_open(input_dev, &inputdev);
        if (retval) {
            ovs_fatal(retval, "%s: failed to open input device", input_dev);
        }
    } else {
        inputdev = NULL;
    }

    /* Open pty master. */
    pty_fd = tty_open_master_pty();
    if (pty_fd < 0) {
        ovs_fatal(-pty_fd, "failed to open master pty");
    }
    tty_set_window_size(pty_fd, 2, 40);

    /* Start child process. */
    if (argc < 1) {
        char *child_argv[2];

        child_argv[0] = getenv("SHELL");
        if (!child_argv[0]) {
            child_argv[0] = "/bin/sh";
        }
        child_argv[1] = NULL;
        retval = tty_fork_child(pty_fd, child_argv);
    } else {
        retval = tty_fork_child(pty_fd, argv);
    }
    if (retval) {
        ovs_fatal(retval, "failed to fork child process");
    }

    die_if_already_running();
    daemonize();

    terminal = terminal_create();
    updater = updater_create();
    scanner = scanner_create();
    ezio_init(&ezio);
    for (i = 0; i < 8; i++) {
        ezio_set_default_icon(&ezio, i);
    }
    byteq_init(&inputq);
    for (;;) {
        /* Get button presses and keyboard input into inputq, then push the
         * inputq to the pty. */
        handle_buttons(updater, scanner, &inputq, &ezio);
        if (inputdev) {
            retval = inputdev_run(inputdev, &inputq);
            if (retval) {
                VLOG_ERR("error reading from input device: %s",
                         strerror(retval));
                inputdev_close(inputdev);
                inputdev = NULL;
            }
        }
        retval = byteq_write(&inputq, pty_fd);
        if (retval && retval != EAGAIN) {
            VLOG_ERR("error passing through input: %s",
                     retval == EOF ? "end of file" : strerror(retval));
        }

        /* Process data from pty in terminal emulator. */
        retval = terminal_run(terminal, &ezio, pty_fd);
        if (retval) {
            VLOG_ERR("error reading from terminal: %s",
                     retval == EOF ? "end of file" : strerror(retval));
            break;
        }

        /* Scroll left and right through text. */
        scanner_run(scanner, &ezio);

        /* Update the display to match what should be shown. */
        retval = updater_run(updater, &ezio, ezio_fd);
        if (retval) {
            VLOG_ERR("error writing to ezio: %s",
                     retval == EOF ? "end of file" : strerror(retval));
            break;
        }
        if (inputdev) {
            inputdev_update(inputdev, &ezio);
        }

        /* Wait for something to happen. */
        terminal_wait(terminal, pty_fd);
        scanner_wait(scanner);
        if (updater_has_buttons(updater)) {
            poll_immediate_wake();
        }
        updater_wait(updater, ezio_fd);
        if (!byteq_is_empty(&inputq)) {
            poll_fd_wait(pty_fd, POLLOUT);
        }
        if (inputdev) {
            inputdev_wait(inputdev);
        }
        poll_block();
    }
    terminal_destroy(terminal);
    updater_destroy(updater);
    scanner_destroy(scanner);

    return 0;
}

static void
send_keys(struct byteq *q, const char *s)
{
    size_t n = strlen(s);
    if (byteq_avail(q) >= n) {
        byteq_putn(q, s, n);
    }
}

static void
handle_buttons(struct updater *up, struct scanner *s,
               struct byteq *q, struct ezio *ezio)
{
    while (updater_has_buttons(up)) {
        int btns = updater_get_buttons(up);
        switch (btns) {
        case BTN_UP:
            send_keys(q, "\x1b\x5b\x41"); /* Up arrow. */
            break;

        case BTN_UP | BTN_ESC:
            send_keys(q, "\x1b[5~"); /* Page up. */
            break;

        case BTN_DOWN:
            send_keys(q, "\x1b\x5b\x42"); /* Down arrow. */
            break;

        case BTN_DOWN | BTN_ESC:
            send_keys(q, "\x1b[6~"); /* Page down. */
            break;

        case BTN_ENTER:
            send_keys(q, "\r");
            break;

        case BTN_ESC:
            send_keys(q, "\x7f");
            break;

        case BTN_UP | BTN_DOWN:
            scanner_left(s, ezio);
            break;

        case BTN_ESC | BTN_ENTER:
            scanner_right(s, ezio);
            break;

        case BTN_UP | BTN_DOWN | BTN_ENTER | BTN_ESC:
            send_keys(q, "\x04"); /* End of file. */
            break;

        case BTN_UP | BTN_ENTER | BTN_ESC:
            send_keys(q, "y");
            break;

        case BTN_DOWN | BTN_ENTER | BTN_ESC:
            send_keys(q, "n");
            break;
        }
    }
}

/* EZIO screen updater. */

/* EZIO command codes. */
#define EZIO_CMD                0xfe /* Command prefix byte. */
#define EZIO_CLEAR              0x01 /* Clear screen. */
#define EZIO_HOME               0x02 /* Move to (0, 0). */
#define EZIO_READ               0x06 /* Poll keyboard. */

#define EZIO_ENTRY_MODE         0x04 /* Set entry mode: */
#define   EZIO_LTOR_MODE        0x02 /* ...left-to-right (vs. r-to-l). */
#define   EZIO_SHIFT_MODE       0x01 /* ...scroll with output (vs. don't). */

#define EZIO_DISPLAY_MODE       0x08 /* Set display mode: */
#define   EZIO_ENABLE_DISPLAY   0x04 /* ...turn on display (vs. blank). */
#define   EZIO_SHOW_CURSOR      0x02 /* ...show cursor (vs. hide). */
#define   EZIO_BLOCK_CURSOR     0x01 /* ...block cursor (vs. underline). */

#define EZIO_INIT               0x28 /* Initialize EZIO. */

#define EZIO_MOVE_CURSOR        0x80 /* Set cursor position. */
#define   EZIO_COL_SHIFT        0    /* Shift count for column (0-based). */
#define   EZIO_ROW_SHIFT        6    /* Shift count for row (0-based). */

#define EZIO_DEFINE_ICON        0x40 /* Define icon. */
#define   EZIO_ICON_SHIFT       3    /* Shift count for icon number (0-7). */

#define EZIO_SCROLL_LEFT        0x18 /* Scroll display left 1 position. */
#define EZIO_SCROLL_RIGHT       0x1c /* Scroll display right 1 position. */
#define EZIO_CURSOR_LEFT        0x10 /* Move cursor left 1 position. */
#define EZIO_CURSOR_RIGHT       0x14 /* Move cursor right 1 position. */

/* Rate limiting: the EZIO runs at 2400 bps, which is 240 bytes per second.
 * Kernel tty buffers, on the other hand, tend to be at least 4 kB.  That
 * means that, if we keep the kernel buffer filled, then the queued data will
 * be 4,096 kB / 240 bytes/s ~= 17 seconds ahead of what is actually
 * displayed.  This is not a happy situation.  So we rate-limit with a token
 * bucket.
 *
 * The parameters below work out as: (6 tokens/ms * 1000 ms) / (25
 * tokens/byte) = 240 bytes/s. */
#define UP_TOKENS_PER_MS 6       /* Tokens acquired per millisecond. */
#define UP_BUCKET_SIZE (6 * 100) /* Capacity of the token bukect. */
#define UP_TOKENS_PER_BYTE 25    /* Tokens required to output a byte. */

struct updater {
    /* Current state of EZIO device. */
    struct ezio visible;

    /* Output state. */
    struct byteq obuf;          /* Output being sent to serial port. */
    int tokens;                 /* Token bucket content. */
    long long int last_fill;    /* Last time we increased 'tokens'.*/
    bool up_to_date;            /* Does visible state match shadow state? */

    /* Input state. */
    struct byteq ibuf;           /* Queued button pushes. */
    long long int last_poll;     /* Last time we sent a button poll request. */
    enum btn_status last_status; /* Last received button status. */
    long long int last_change;   /* Time when status most recently changed. */
    int repeat_count;            /* Autorepeat count. */
    bool releasing;              /* Waiting for button release? */
};

static void send_command(struct updater *, uint8_t command);
static void recv_button_state(struct updater *, enum btn_status status);
static int range(int value, int min, int max);
static void send_command(struct updater *, uint8_t command);
static void set_cursor_position(struct updater *, int x, int y);
static bool icons_differ(const struct ezio *, const struct ezio *, int *idx);
static void update_char(struct updater *, const struct ezio *, int x, int y);
static void update_cursor_status(struct updater *, const struct ezio *);

/* Creates and returns a new updater. */
static struct updater *
updater_create(void)
{
    struct updater *up = xmalloc(sizeof *up);
    ezio_init(&up->visible);
    byteq_init(&up->obuf);
    up->tokens = UP_BUCKET_SIZE;
    up->last_fill = time_msec();
    byteq_init(&up->ibuf);
    up->last_poll = LLONG_MIN;
    up->last_status = 0;
    up->last_change = time_msec();
    up->releasing = false;
    send_command(up, EZIO_INIT);
    send_command(up, EZIO_INIT);
    send_command(up, EZIO_CLEAR);
    send_command(up, EZIO_HOME);
    return up;
}

/* Destroys updater 'up. */
static void
updater_destroy(struct updater *up)
{
    free(up);
}

/* Sends EZIO commands over file descriptor 'ezio_fd' to the EZIO represented
 * by updater 'up', to make the EZIO display the contents of 'shadow'.
 * Rate-limiting can cause the update to be only partial, but the next call to
 * updater_run() will resume the update.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
static int
updater_run(struct updater *up, const struct ezio *shadow, int ezio_fd)
{
    uint8_t c;
    while (read(ezio_fd, &c, 1) > 0) {
        if ((c & 0xf0) == 0xb0) {
            recv_button_state(up, ~c & 0x0f);
        }
    }

    up->up_to_date = false;
    for (;;) {
        struct ezio *visible = &up->visible;
        int idx, x, y;
        int retval;

        /* Flush the buffer out to the EZIO device. */
        retval = byteq_write(&up->obuf, ezio_fd);
        if (retval == EAGAIN) {
            return 0;
        } else if (retval) {
            VLOG_WARN("error writing ezio: %s", strerror(retval));
            return retval;
        }

        /* Make sure we have some tokens before we write anything more. */
        if (up->tokens <= 0) {
            long long int now = time_msec();
            if (now > up->last_fill) {
                up->tokens += (now - up->last_fill) * UP_TOKENS_PER_MS;
                up->last_fill = now;
                if (up->tokens > UP_BUCKET_SIZE) {
                    up->tokens = UP_BUCKET_SIZE;
                }
            }
            if (up->tokens <= 0) {
                /* Still out of tokens. */
                return 0;
            }
        }

        /* Consider what else we might want to send. */
        if (time_msec() >= up->last_poll + 100) {
            /* Send a button-read command. */
            send_command(up, EZIO_READ);
            up->last_poll = time_msec();
        } else if (visible->show_cursor && !shadow->show_cursor) {
            /* Turn off the cursor. */
            update_cursor_status(up, shadow);
        } else if (icons_differ(shadow, visible, &idx)) {
            /* Update the icons. */
            send_command(up, EZIO_DEFINE_ICON + (idx << EZIO_ICON_SHIFT));
            byteq_putn(&up->obuf, &shadow->icons[idx][0], 8);
            set_cursor_position(up, shadow->x, shadow->y);
            memcpy(visible->icons[idx], shadow->icons[idx], 8);
        } else if (visible->x_ofs != shadow->x_ofs) {
            /* Scroll to the correct horizontal position. */
            if (visible->x_ofs < shadow->x_ofs) {
                send_command(up, EZIO_SCROLL_LEFT);
                visible->x_ofs++;
            } else {
                send_command(up, EZIO_SCROLL_RIGHT);
                visible->x_ofs--;
            }
        } else if (ezio_chars_differ(shadow, visible, shadow->x_ofs,
                                     shadow->x_ofs + 16, &x, &y)) {
            /* Update the visible region. */
            update_char(up, shadow, x, y);
        } else if (ezio_chars_differ(shadow, visible, 0, 40, &x, &y)) {
            /* Update the off-screen region. */
            update_char(up, shadow, x, y);
        } else if ((visible->x != shadow->x || visible->y != shadow->y)
                   && shadow->show_cursor) {
            /* Update the cursor position.  (This has to follow updating the
             * display content, because updating display content changes the
             * cursor position.) */
            set_cursor_position(up, shadow->x, shadow->y);
        } else if (visible->show_cursor != shadow->show_cursor
                   || visible->blink_cursor != shadow->blink_cursor) {
            /* Update the cursor type. */
            update_cursor_status(up, shadow);
        } else {
            /* We're fully up-to-date. */
            up->up_to_date = true;
            return 0;
        }
        up->tokens -= UP_TOKENS_PER_BYTE * byteq_used(&up->obuf);
    }
}

/* Calls poll-loop functions that will cause poll_block() to wake up when
 * updater_run() has work to do. */
static void
updater_wait(struct updater *up, int ezio_fd)
{
    if (!byteq_is_empty(&up->obuf)) {
        poll_fd_wait(ezio_fd, POLLOUT);
    } else if (up->tokens <= 0) {
        poll_timer_wait((-up->tokens / UP_TOKENS_PER_MS) + 1);
    } else if (!up->up_to_date) {
        poll_immediate_wake();
    }

    if (!up->last_status && time_msec() - up->last_change > 100) {
        /* No button presses in a while.  Sleep longer. */
        poll_timer_wait(100);
    } else {
        poll_timer_wait(50);
    }
}

/* Returns a button or buttons that were pushed.  Must not be called if
 * updater_has_buttons() would return false.  One or more BTN_* flags will be
 * set in the return value. */
enum btn_status
updater_get_buttons(struct updater *up)
{
    return byteq_get(&up->ibuf);
}

/* Any buttons pushed? */
bool
updater_has_buttons(const struct updater *up)
{
    return !byteq_is_empty(&up->ibuf);
}

/* Adds 'btns' to the queue of pushed buttons */
static void
buttons_pushed(struct updater *up, enum btn_status btns)
{
    if (!byteq_is_full(&up->ibuf)) {
        byteq_put(&up->ibuf, btns);
    }
}

/* Updates the buttons-pushed queue based on the current button 'status'. */
static void
recv_button_state(struct updater *up, enum btn_status status)
{
    /* Calculate milliseconds since button status last changed. */
    long long int stable_msec;
    if (status != up->last_status) {
        up->last_change = time_msec();
        stable_msec = 0;
    } else {
        stable_msec = time_msec() - up->last_change;
    }

    if (up->releasing) {
        if (!status) {
            up->releasing = false;
        }
    } else if (up->last_status) {
        if (!(status & up->last_status)) {
            /* Button(s) were pushed and released. */
            if (!up->repeat_count) {
                buttons_pushed(up, up->last_status);
            }
        } else if (stable_msec >= 150 && !up->repeat_count) {
            /* Buttons have been stable for a while, so push them once. */
            buttons_pushed(up, status);
            up->repeat_count++;
        } else if (stable_msec >= 1000) {
            /* Autorepeat 10/second after 1 second hold time. */
            int n = (stable_msec - 1000) / 100 + 1;
            while (up->repeat_count < n) {
                buttons_pushed(up, status);
                up->repeat_count++;
            }
        } else if ((status & up->last_status) == up->last_status) {
            /* More buttons pushed than at last poll. */
        } else {
            /* Some, but not all, buttons were released.  Ignore the buttons
             * until all are released. */
            up->releasing = true;
        }
    }
    if (!status) {
        up->repeat_count = 0;
    }
    up->last_status = status;
}

static int
range(int value, int min, int max)
{
    return value < min ? min : value > max ? max : value;
}

static void
send_command(struct updater *up, uint8_t command)
{
    byteq_put(&up->obuf, EZIO_CMD);
    byteq_put(&up->obuf, command);
}

/* Moves the cursor to 0-based position (x, y).  Updates 'up->visible' to
 * reflect the change. */
static void
set_cursor_position(struct updater *up, int x, int y)
{
    int command = EZIO_MOVE_CURSOR;
    command |= range(x, 0, 39) << EZIO_COL_SHIFT;
    command |= range(y, 0, 1) << EZIO_ROW_SHIFT;
    send_command(up, command);
    up->visible.x = x;
    up->visible.y = y;
}

/* If any of the icons differ from 'a' to 'b', returns true and sets '*idx' to
 * the index of the first icon that differs.  Otherwise, returns false.  */
static bool
icons_differ(const struct ezio *a, const struct ezio *b, int *idx)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(a->icons); i++) {
        if (memcmp(&a->icons[i], &b->icons[i], sizeof a->icons[i])) {
            *idx = i;
            return true;
        }
    }
    return false;
}

/* Queues commands in 'up''s output buffer to update the character at 0-based
 * position (x,y) to match the character that 'shadow' has there.  Updates
 * 'up->visible' to reflect the change. */
static void
update_char(struct updater *up, const struct ezio *shadow, int x, int y)
{
    if (x != up->visible.x || y != up->visible.y) {
        set_cursor_position(up, x, y);
    }
    byteq_put(&up->obuf, shadow->chars[y][x]);
    up->visible.chars[y][x] = shadow->chars[y][x];
    up->visible.x++;
}

/* Queues commands in 'up''s output buffer to change the EZIO's cursor shape to
 * match that in 'shadow'.  Updates 'up->visible' to reflect the change. */
static void
update_cursor_status(struct updater *up, const struct ezio *shadow)
{
    uint8_t command = EZIO_DISPLAY_MODE | EZIO_ENABLE_DISPLAY;
    if (shadow->show_cursor) {
        command |= EZIO_SHOW_CURSOR;
        if (shadow->blink_cursor) {
            command |= EZIO_BLOCK_CURSOR;
        }
    }
    send_command(up, command);
    up->visible.show_cursor = shadow->show_cursor;
    up->visible.blink_cursor = shadow->blink_cursor;
}

/* An input device, such as a tty. */

struct inputdev {
    /* Input. */
    int fd;                     /* File descriptor. */

    /* State for mirroring the EZIO display to the device. */
    bool is_tty;                /* We only attempt to mirror to ttys. */
    struct byteq outq;          /* Output queue. */
    struct ezio visible;        /* Data that we have displayed. */
};

/* Opens 'name' as a input device.  If successful, returns 0 and stores a
 * pointer to the input device in '*devp'.  On failure, returns a positive
 * errno value. */
static int
inputdev_open(const char *name, struct inputdev **devp)
{
    struct inputdev *dev;
    int retval;
    int fd;

    *devp = NULL;
    if (!strcmp(name, "vt")) {
        fd = vt_open(O_RDWR | O_NOCTTY);
        if (fd < 0) {
            return -fd;
        }
    } else if (!strcmp(name, "-")) {
        fd = dup(STDIN_FILENO);
        if (fd < 0) {
            return errno;
        }
    } else {
        fd = open(name, O_RDWR | O_NOCTTY);
        if (fd < 0) {
            return errno;
        }
    }

    retval = tty_set_raw_mode(fd, B0);
    if (retval) {
        close(fd);
        VLOG_WARN("%s: failed to configure tty parameters: %s",
                  name, strerror(retval));
        return retval;
    }

    dev = xmalloc(sizeof *dev);
    dev->fd = fd;
    dev->is_tty = isatty(fd);
    byteq_init(&dev->outq);
    ezio_init(&dev->visible);
    *devp = dev;
    return 0;
}

/* Closes and destroys input device 'dev'. */
static void
inputdev_close(struct inputdev *dev)
{
    if (dev) {
        close(dev->fd);
        free(dev);
    }
}

/* Reads input from 'dev' into 'q'.  Returns 0 if successful, otherwise a
 * positive errno value. */
static int
inputdev_run(struct inputdev *dev, struct byteq *q)
{
    int retval = byteq_read(q, dev->fd);
    return retval == EAGAIN ? 0 : retval;
}

/* Dumps data from 'dev''s output queue to the underlying file descriptor,
 * updating the tty screen display. */
static void
flush_inputdev(struct inputdev *dev)
{
    int retval = byteq_write(&dev->outq, dev->fd);
    if (retval && retval != EAGAIN) {
        VLOG_WARN("error writing input device, "
                  "disabling further output");
        dev->is_tty = false;
    }
}

/* Updates the tty screen display on 'dev' to match 'e'. */
static void
inputdev_update(struct inputdev *dev, const struct ezio *e)
{
    struct byteq *q = &dev->outq;
    int x, y;

    if (!dev->is_tty) {
        return;
    }

    flush_inputdev(dev);
    if (!byteq_is_empty(q)) {
        return;
    }

    if (!ezio_chars_differ(e, &dev->visible, 0, 40, &x, &y)
        && e->x == dev->visible.x
        && e->y == dev->visible.y
        && e->x_ofs == dev->visible.x_ofs
        && e->show_cursor == dev->visible.show_cursor) {
        return;
    }
    dev->visible = *e;

    byteq_put_string(q, "\033[H\033[2J"); /* Clear screen. */
    for (y = 0; y < 4; y++) {
        byteq_put(q, "+||+"[y]);
        for (x = 0; x < 40; x++) {
            int c;
            if (x == e->x_ofs) {
                byteq_put(q, '[');
            }
            c = y == 0 || y == 3 ? '-' : e->chars[y - 1][x];
            if (c == 6) {
                c = '\\';
            } else if (c == 7) {
                c = '~';
            } else if (c < 0x20 || c > 0x7d) {
                c = '?';
            }
            byteq_put(q, c);
            if (x == e->x_ofs + 15) {
                byteq_put(q, ']');
            }
        }
        byteq_put(q, "+||+"[y]);
        byteq_put(q, '\r');
        byteq_put(q, '\n');
    }
    if (e->show_cursor) {
        int x = range(e->x, 0, 39) + 2 + (e->x >= e->x_ofs) + (e->x > e->x_ofs + 15);
        int y = range(e->y, 0, 1) + 2;
        char cup[16];
        sprintf(cup, "\033[%d;%dH", y, x); /* Position cursor. */
        byteq_put_string(q, cup);
    }
    flush_inputdev(dev);
}

/* Calls poll-loop functions that will cause poll_block() to wake up when
 * inputdev_run() has work to do. */
static void
inputdev_wait(struct inputdev *dev)
{
    int flags = POLLIN;
    if (dev->is_tty && !byteq_is_empty(&dev->outq)) {
        flags |= POLLOUT;
    }
    poll_fd_wait(dev->fd, flags);
}

/* Scrolls the display left and right automatically to display all the
 * content. */

enum scanner_state {
    SCANNER_LEFT,               /* Moving left. */
    SCANNER_RIGHT               /* Moving right. */
};

struct scanner {
    enum scanner_state state;   /* Current state. */
    int wait;                   /* No. of cycles to pause before continuing. */
    long long int last_move;    /* Last time the state machine ran. */
};

static void find_min_max(struct ezio *, int *min, int *max);

static struct scanner *
scanner_create(void)
{
    struct scanner *s = xmalloc(sizeof *s);
    s->state = SCANNER_RIGHT;
    s->wait = 0;
    s->last_move = LLONG_MIN;
    return s;
}

static void
scanner_destroy(struct scanner *s)
{
    free(s);
}

static void
scanner_run(struct scanner *s, struct ezio *ezio)
{
    long long int now = time_msec();
    if (now >= s->last_move + 750) {
        s->last_move = now;
        if (s->wait) {
            s->wait--;
        } else {
            int min, max;

            find_min_max(ezio, &min, &max);
            if (max - min + 1 <= 16) {
                ezio->x_ofs = min;
                return;
            }

            switch (s->state) {
            case SCANNER_RIGHT:
                if (ezio->x_ofs + 15 < max) {
                    ezio->x_ofs++;
                } else {
                    s->state = SCANNER_LEFT;
                    s->wait = 1;
                }
                break;

            case SCANNER_LEFT:
                if (ezio->x_ofs > min) {
                    ezio->x_ofs--;
                } else {
                    s->state = SCANNER_RIGHT;
                    s->wait = 1;
                }
                break;
            }
        }
    }
}

static void
scanner_wait(struct scanner *s)
{
    long long int now = time_msec();
    long long int expires = s->last_move + 750;
    if (now >= expires) {
        poll_immediate_wake();
    } else {
        poll_timer_wait(expires - now);
    }

}

static void
scanner_left(struct scanner *s, struct ezio *ezio)
{
    s->wait = 7;
    if (ezio->x_ofs > 0) {
        ezio->x_ofs--;
    }
}

static void
scanner_right(struct scanner *s, struct ezio *ezio)
{
    s->wait = 7;
    if (ezio->x_ofs < 40 - 16) {
        ezio->x_ofs++;
    }
}

static void
find_min_max(struct ezio *ezio, int *min, int *max)
{
    int x;

    *min = 0;
    for (x = 0; x < 40; x++) {
        if (ezio->chars[0][x] != ' ' || ezio->chars[1][x] != ' ') {
            *min = x;
            break;
        }
    }

    *max = 15;
    for (x = 39; x >= 0; x--) {
        if (ezio->chars[0][x] != ' ' || ezio->chars[1][x] != ' ') {
            *max = x;
            break;
        }
    }

    if (ezio->show_cursor) {
        if (ezio->x < *min) {
            *min = ezio->x;
        }
        if (ezio->x > *max) {
            *max = ezio->x;
        }
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_DUMMY = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"ezio3", required_argument, 0, 'e'},
        {"input", required_argument, 0, 'i'},
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'e':
            ezio_dev = optarg;
            break;

        case 'i':
            input_dev = optarg ? optarg : "-";
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS

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
    printf("%s: EZIO3 terminal front-end\n"
           "Provides a front-end to a 16x2 EZIO3 LCD display that makes\n"
           "it look more like a conventional terminal\n"
           "usage: %s [OPTIONS] [-- COMMAND [ARG...]]\n"
           "where COMMAND is a command to run with stdin, stdout, and\n"
           "stderr directed to the EZIO3 display.\n"
           "\nSettings (defaults in parentheses):\n"
           "  -e, --ezio=TTY         set EZIO3 serial device (/dev/ttyS1)\n"
           "  -i, --input=TERMINAL   also read input from TERMINAL;\n"
           "                         specify - for stdin, or vt to allocate\n"
           "                         and switch to a free virtual terminal\n"
           "\nOther options:\n"
           "  -v, --verbose=MODULE:FACILITY:LEVEL  configure logging levels\n"
           "  -v, --verbose               set maximum verbosity level\n"
           "  -h, --help             display this help message\n"
           "  -V, --version          display version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}
