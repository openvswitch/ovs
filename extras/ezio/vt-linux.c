/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
 *
 */

#include <config.h>
#include "extras/ezio/vt.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "util.h"

#define THIS_MODULE VLM_vt
#include "vlog.h"

static bool get_console_fd(int *fd);

int
vt_open(int open_flags)
{
    int console_fd, vt_fd;
    char name[16];
    int vt;

    if (!get_console_fd(&console_fd)) {
        return -EACCES;
    }

    /* Deallocate all unused virtual terminals, so that we don't proliferate an
     * excess of empty ones over multiple runs. */
    if (ioctl(console_fd, VT_DISALLOCATE, 0) < 0) {
        VLOG_WARN("failed to deallocate empty virtual terminals: %s",
                  strerror(errno));
    }

    /* Find a unused virtual terminal. */
    if (ioctl(console_fd, VT_OPENQRY, &vt) < 0) {
        int error = errno;
        VLOG_ERR("failed to find a free virtual terminal: %s",
                 strerror(error));
        close(console_fd);
        return -error;
    }

    /* Open virtual terminal. */
    sprintf(name, "/dev/tty%d", vt);
    vt_fd = open(name, open_flags);
    if (vt_fd < 0) {
        int error = errno;
        VLOG_ERR("failed to open %s: %s", name, strerror(error));
        close(console_fd);
        return -error;
    }

    /* Activate virtual terminal. */
    if (ioctl(console_fd, VT_ACTIVATE, vt) < 0
        || ioctl(console_fd, VT_WAITACTIVE, vt) < 0) {
        int error = errno;
        VLOG_ERR("could not activate virtual terminal %d: %s",
                 vt, strerror(error));
        close(console_fd);
        close(vt_fd);
        return -error;
    }

    /* Success. */
    VLOG_DBG("allocated virtual terminal %d (%s)", vt, name);
    close(console_fd);
    return vt_fd;
}

static bool
is_console(int fd)
{
    uint8_t type = 0;
    return !ioctl(fd, KDGKBTYPE, &type) && (type == KB_101 || type == KB_84);
}

static bool
open_console(const char *name, int *fdp)
{
    *fdp = open(name, O_RDWR | O_NOCTTY);
    if (*fdp >= 0) {
        if (is_console(*fdp)) {
            return true;
        }
        close(*fdp);
    }
    return false;
}

static bool
get_console_fd(int *fdp)
{
    int fd;

    if (open_console("/dev/tty", fdp)
        || open_console("/dev/tty0", fdp)
        || open_console("/dev/console", fdp)) {
        return true;
    }
    for (fd = 0; fd < 3; fd++) {
        if (is_console(fd)) {
            *fdp = dup(fd);
            if (*fdp >= 0) {
                return true;
            }
        }
    }
    VLOG_ERR("unable to obtain a file descriptor for the console");
    return false;
}
