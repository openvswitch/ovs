/*
 * Copyright (c) 2014 Nicira, Inc.
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
#ifndef DPCTL_H
#define DPCTL_H 1

#include <stdbool.h>

#include "compiler.h"

struct dpctl_params {
    /* True if it is called by ovs-appctl command. */
    bool is_appctl;

    /* -s, --statistics: Print port/flow statistics? */
    bool print_statistics;

    /* --clear: Reset existing statistics to zero when modifying a flow? */
    bool zero_statistics;

    /* --may-create: Allow mod-flows command to create a new flow? */
    bool may_create;

    /* --read-only: Do not run R/W commands? */
    bool read_only;

    /* -m, --more: Increase output verbosity. */
    int verbosity;

    /* --names: Use port names in output? */
    bool names;

    /* Callback for printing.  This function is called from dpctl_run_command()
     * to output data.  The 'aux' parameter is set to the 'aux'
     * member.  The 'error' parameter is true if 'string' is an error
     * message, false otherwise */
    void (*output)(void *aux, bool error, const char *string);
    void *aux;

    /* 'usage' (if != NULL) gets called for the "help" command. */
    void (*usage)(void *aux);
};

int dpctl_run_command(int argc, const char *argv[],
                      struct dpctl_params *dpctl_p);

void dpctl_unixctl_register(void);

#endif /* dpctl.h */
