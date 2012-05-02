/* Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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

#include "entropy.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(entropy);

static const char urandom[] = "/dev/urandom";

/* Initializes 'buffer' with 'n' bytes of high-quality random numbers.  Returns
 * 0 if successful, otherwise a positive errno value or EOF on error. */
int
get_entropy(void *buffer, size_t n)
{
    size_t bytes_read;
    int error;
    int fd;

    fd = open(urandom, O_RDONLY);
    if (fd < 0) {
        VLOG_ERR("%s: open failed (%s)", urandom, strerror(errno));
        return errno ? errno : EINVAL;
    }

    error = read_fully(fd, buffer, n, &bytes_read);
    close(fd);

    if (error) {
        VLOG_ERR("%s: read error (%s)", urandom, ovs_retval_to_string(error));
    }
    return error;
}

/* Initializes 'buffer' with 'n' bytes of high-quality random numbers.  Exits
 * if an error occurs. */
void
get_entropy_or_die(void *buffer, size_t n)
{
    int error = get_entropy(buffer, n);
    if (error) {
        VLOG_FATAL("%s: read error (%s)",
                   urandom, ovs_retval_to_string(error));
    }
}
