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

#include <config.h>
#include "daemon.h"
#include <stdio.h>
#include <stdlib.h>
#include "poll-loop.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(daemon);

static bool detach;             /* Was --service specified? */
static bool detached;           /* Have we already detached? */

/* --service-monitor: Should the service be restarted if it dies
 * unexpectedly? */
static bool monitor;

/* Handle to the Services Manager and the created service. */
static SC_HANDLE manager, service;

/* Handle to the status information structure for the current service. */
static SERVICE_STATUS_HANDLE hstatus;

/* Hold the service's current status. */
static SERVICE_STATUS service_status;

/* Handle to an event object used to wakeup from poll_block(). */
static HANDLE wevent;

/* Hold the arguments sent to the main function. */
static int sargc;
static char ***sargvp;

static void check_service(void);
static void handle_scm_callback(void);
static void init_service_status(void);
static void set_config_failure_actions(void);

extern int main(int argc, char *argv[]);

void
daemon_usage(void)
{
    printf(
        "\nService options:\n"
        "  --service               run in background as a service.\n"
        "  --service-monitor       restart the service in case of an "
                                   "unexpected failure. \n",
        ovs_rundir(), program_name);
}

/* Registers the call-back and configures the actions in case of a failure
 * with the Windows services manager. */
void
service_start(int *argcp, char **argvp[])
{
    int argc = *argcp;
    char **argv = *argvp;
    int i;
    SERVICE_TABLE_ENTRY service_table[] = {
        {(LPTSTR)program_name, (LPSERVICE_MAIN_FUNCTION)main},
        {NULL, NULL}
    };

    /* 'detached' is 'false' when service_start() is called the first time.
     * It is 'true', when it is called the second time by the Windows services
     * manager. */
    if (detached) {
        init_service_status();

        wevent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!wevent) {
            char *msg_buf = ovs_lasterror_to_string();
            VLOG_FATAL("Failed to create a event (%s).", msg_buf);
        }

        poll_fd_wait_event(0, wevent, POLLIN);

        /* Register the control handler. This function is called by the service
         * manager to stop the service. */
        hstatus = RegisterServiceCtrlHandler(program_name,
                                         (LPHANDLER_FUNCTION)control_handler);
        if (!hstatus) {
            char *msg_buf = ovs_lasterror_to_string();
            VLOG_FATAL("Failed to register the service control handler (%s).",
                        msg_buf);
        }

        if (monitor) {
            set_config_failure_actions();
        }

        /* When the service control manager does the call back, it does not
         * send the same arguments as sent to the main function during the
         * service start. So, use the arguments passed over during the first
         * time. */
        *argcp = sargc;
        *argvp = *sargvp;

        /* XXX: Windows implementation cannot have a unixctl commands in the
        * traditional sense of unix domain sockets. If an implementation is
        * done that involves 'unixctl' vlog commands the following call is
        * needed to make sure that the unixctl commands for vlog get
        * registered in a daemon, even before the first log message. */
        vlog_init();

        return;
    }

    assert_single_threaded();

    /* A reference to arguments passed to the main function the first time.
     * We need it after the call-back from service control manager. */
    sargc = argc;
    sargvp = argvp;

    /* We are only interested in the '--service' and '--service-monitor'
     * options before the call-back from the service control manager. */
    for (i = 0; i < argc; i ++) {
        if (!strcmp(argv[i], "--service")) {
            detach = true;
        } else if (!strcmp(argv[i], "--service-monitor")) {
            monitor = true;
        }
    }

    /* If '--service' is not a command line option, run in foreground. */
    if (!detach) {
        return;
    }

    /* If we have been configured to run as a service, then that service
     * should already have been created either manually or through a start up
     * script. */
    check_service();

    detached = true;

    /* StartServiceCtrlDispatcher blocks and returns after the service is
     * stopped. */
    if (!StartServiceCtrlDispatcher(service_table)) {
        char *msg_buf = ovs_lasterror_to_string();
        VLOG_FATAL("Failed at StartServiceCtrlDispatcher (%s)", msg_buf);
    }
    exit(0);
}

/* This function is registered with the Windows services manager through
 * a call to RegisterServiceCtrlHandler() and will be called by the Windows
 * services manager asynchronously to stop the service. */
void
control_handler(DWORD request)
{
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        service_status.dwCurrentState = SERVICE_STOPPED;
        service_status.dwWin32ExitCode = NO_ERROR;
        SetEvent(wevent);
        break;

    default:
        break;
    }
}

/* Return 'true' if the Windows services manager has called the
 * control_handler() and asked the program to terminate. */
bool
should_service_stop(void)
{
    if (detached) {
        if (service_status.dwCurrentState != SERVICE_RUNNING) {
            return true;
        } else {
            poll_fd_wait_event(0, wevent, POLLIN);
        }
    }
    return false;
}

/* Set the service as stopped. The control manager will terminate the
 * service soon after this call. Hence, this should ideally be the last
 * call before termination. */
void
service_stop()
{
    ResetEvent(wevent);
    CloseHandle(wevent);

    service_status.dwCurrentState = SERVICE_STOPPED;
    service_status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(hstatus, &service_status);
}

/* Call this function to signal that the daemon is ready. init_service()
 * or control_handler() has already initalized/set the
 * service_status.dwCurrentState .*/
static void
service_complete(void)
{
    if (hstatus) {
        SetServiceStatus(hstatus, &service_status);
    }
}

/* Check whether 'program_name' has been created as a service. */
static void
check_service()
{
    /* Establish a connection to the local service control manager. */
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!manager) {
        char *msg_buf = ovs_lasterror_to_string();
        VLOG_FATAL("Failed to open the service control manager (%s).",
                   msg_buf);
    }

    service = OpenService(manager, program_name, SERVICE_ALL_ACCESS);
    if (!service) {
        char *msg_buf = ovs_lasterror_to_string();
        VLOG_FATAL("Failed to open service (%s).", msg_buf);
    }
}

/* Service status of a service can be checked asynchronously through
 * tools like 'sc' or through Windows services manager and is set
 * through a call to SetServiceStatus(). */
static void
init_service_status()
{
    /* The service runs in its own process. */
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    /* The control codes the service accepts. */
    service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                            SERVICE_ACCEPT_SHUTDOWN;

    /* Initialize the current state as SERVICE_RUNNING. */
    service_status.dwCurrentState = SERVICE_RUNNING;

    /* The exit code to indicate if there was an error. */
    service_status.dwWin32ExitCode = NO_ERROR;

    /* The checkpoint value the service increments periodically. Set as 0
     * as we do not plan to periodically increment the value. */
    service_status.dwCheckPoint = 0;

    /* The estimated time required for the stop operation in ms. */
    service_status.dwWaitHint = 1000;
}

/* In case of an unexpected termination, configure the action to be
 * taken. */
static void
set_config_failure_actions()
{
    /* In case of a failure, restart the process the first two times
     * After 'dwResetPeriod', the failure count is reset. */
    SC_ACTION fail_action[3] = {
        {SC_ACTION_RESTART, 0},
        {SC_ACTION_RESTART, 0},
        {SC_ACTION_NONE, 0}
    };
    SERVICE_FAILURE_ACTIONS service_fail_action;

    /* Reset failure count after (in seconds). */
    service_fail_action.dwResetPeriod = 10;

    /* Reboot message. */
    service_fail_action.lpRebootMsg = NULL;

    /* The command line of the process. */
    service_fail_action.lpCommand = NULL;

    /* Number of elements in 'fail_actions'. */
    service_fail_action.cActions = sizeof(fail_action)/sizeof(fail_action[0]);

    /* A pointer to an array of SC_ACTION structures. */
    service_fail_action.lpsaActions = fail_action;

    if (!ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS,
                              &service_fail_action)) {
        char *msg_buf = ovs_lasterror_to_string();
        VLOG_FATAL("Failed to configure service fail actions (%s).", msg_buf);
    }
}


/* Stub functions to handle daemonize related calls in non-windows platform. */
bool
get_detach()
{
    return false;
}

void
daemon_save_fd(int fd OVS_UNUSED)
{
}

void
daemonize(void)
{
}

void daemonize_start(void)
{
}

void
daemonize_complete(void)
{
    service_complete();
}
