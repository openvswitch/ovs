/*
 * Copyright (c) 2018 Ilya Maximets <i.maximets@samsung.com>
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

#include "fatal-signal.h"
#include "openvswitch/vlog.h"
#include "stream.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(test_stream);

int
main(int argc, char *argv[])
{
    int error;
    struct stream *stream;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);

    if (argc < 2) {
        ovs_fatal(0, "usage: %s REMOTE", argv[0]);
    }

    error = stream_open_block(stream_open(argv[1], &stream, DSCP_DEFAULT),
                              10000, &stream);
    if (error) {
        VLOG_ERR("stream_open_block(%s) failure: %s",
                 argv[1], ovs_strerror(error));
    }
    stream_close(stream);
    return (error || !stream) ? 1 : 0;
}
