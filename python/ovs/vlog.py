
# Copyright (c) 2011, 2012, 2013 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import logging
import logging.handlers
import re
import socket
import sys

import ovs.dirs
import ovs.unixctl
import ovs.util

FACILITIES = {"console": "info", "file": "info", "syslog": "info"}
LEVELS = {
    "dbg": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "err": logging.ERROR,
    "emer": logging.CRITICAL,
    "off": logging.CRITICAL
}


def get_level(level_str):
    return LEVELS.get(level_str.lower())


class Vlog:
    __inited = False
    __msg_num = 0
    __mfl = {}  # Module -> facility -> level
    __log_file = None
    __file_handler = None

    def __init__(self, name):
        """Creates a new Vlog object representing a module called 'name'.  The
        created Vlog object will do nothing until the Vlog.init() static method
        is called.  Once called, no more Vlog objects may be created."""

        assert not Vlog.__inited
        self.name = name.lower()
        if name not in Vlog.__mfl:
            Vlog.__mfl[self.name] = FACILITIES.copy()

    def __log(self, level, message, **kwargs):
        if not Vlog.__inited:
            return

        dt = datetime.datetime.utcnow();
        now = dt.strftime("%Y-%m-%dT%H:%M:%S.%%03iZ") % (dt.microsecond/1000)
        syslog_message = ("%s|%s|%s|%s"
                           % (Vlog.__msg_num, self.name, level, message))

        level = LEVELS.get(level.lower(), logging.DEBUG)
        Vlog.__msg_num += 1

        for f, f_level in Vlog.__mfl[self.name].iteritems():
            f_level = LEVELS.get(f_level, logging.CRITICAL)
            if level >= f_level:
                if f == "syslog":
                    message = "ovs|" + syslog_message
                else:
                    message = "%s|%s" % (now, syslog_message)
                logging.getLogger(f).log(level, message, **kwargs)

    def emer(self, message, **kwargs):
        self.__log("EMER", message, **kwargs)

    def err(self, message, **kwargs):
        self.__log("ERR", message, **kwargs)

    def warn(self, message, **kwargs):
        self.__log("WARN", message, **kwargs)

    def info(self, message, **kwargs):
        self.__log("INFO", message, **kwargs)

    def dbg(self, message, **kwargs):
        self.__log("DBG", message, **kwargs)

    def __is_enabled(self, level):
        level = LEVELS.get(level.lower(), logging.DEBUG)
        for f, f_level in Vlog.__mfl[self.name].iteritems():
            f_level = LEVELS.get(f_level, logging.CRITICAL)
            if level >= f_level:
                return True
        return False

    def emer_is_enabled(self):
        return self.__is_enabled("EMER")

    def err_is_enabled(self):
        return self.__is_enabled("ERR")

    def warn_is_enabled(self):
        return self.__is_enabled("WARN")

    def info_is_enabled(self):
        return self.__is_enabled("INFO")

    def dbg_is_enabled(self):
        return self.__is_enabled("DBG")

    def exception(self, message):
        """Logs 'message' at ERR log level.  Includes a backtrace when in
        exception context."""
        self.err(message, exc_info=True)

    @staticmethod
    def init(log_file=None):
        """Intializes the Vlog module.  Causes Vlog to write to 'log_file' if
        not None.  Should be called after all Vlog objects have been created.
        No logging will occur until this function is called."""

        if Vlog.__inited:
            return

        Vlog.__inited = True
        logging.raiseExceptions = False
        Vlog.__log_file = log_file
        for f in FACILITIES:
            logger = logging.getLogger(f)
            logger.setLevel(logging.DEBUG)

            try:
                if f == "console":
                    logger.addHandler(logging.StreamHandler(sys.stderr))
                elif f == "syslog":
                    logger.addHandler(logging.handlers.SysLogHandler(
                        address="/dev/log",
                        facility=logging.handlers.SysLogHandler.LOG_DAEMON))
                elif f == "file" and Vlog.__log_file:
                    Vlog.__file_handler = logging.FileHandler(Vlog.__log_file)
                    logger.addHandler(Vlog.__file_handler)
            except (IOError, socket.error):
                logger.setLevel(logging.CRITICAL)

        ovs.unixctl.command_register("vlog/reopen", "", 0, 0,
                                     Vlog._unixctl_vlog_reopen, None)
        ovs.unixctl.command_register("vlog/set", "spec", 1, sys.maxint,
                                     Vlog._unixctl_vlog_set, None)
        ovs.unixctl.command_register("vlog/list", "", 0, 0,
                                     Vlog._unixctl_vlog_list, None)

    @staticmethod
    def set_level(module, facility, level):
        """ Sets the log level of the 'module'-'facility' tuple to 'level'.
        All three arguments are strings which are interpreted the same as
        arguments to the --verbose flag.  Should be called after all Vlog
        objects have already been created."""

        module = module.lower()
        facility = facility.lower()
        level = level.lower()

        if facility != "any" and facility not in FACILITIES:
            return

        if module != "any" and module not in Vlog.__mfl:
            return

        if level not in LEVELS:
            return

        if module == "any":
            modules = Vlog.__mfl.keys()
        else:
            modules = [module]

        if facility == "any":
            facilities = FACILITIES.keys()
        else:
            facilities = [facility]

        for m in modules:
            for f in facilities:
                Vlog.__mfl[m][f] = level

    @staticmethod
    def set_levels_from_string(s):
        module = None
        level = None
        facility = None

        for word in [w.lower() for w in re.split('[ :]', s)]:
            if word == "any":
                pass
            elif word in FACILITIES:
                if facility:
                    return "cannot specify multiple facilities"
                facility = word
            elif word in LEVELS:
                if level:
                    return "cannot specify multiple levels"
                level = word
            elif word in Vlog.__mfl:
                if module:
                    return "cannot specify multiple modules"
                module = word
            else:
                return "no facility, level, or module \"%s\"" % word

        Vlog.set_level(module or "any", facility or "any", level or "any")

    @staticmethod
    def get_levels():
        lines = ["                 console    syslog    file\n",
                 "                 -------    ------    ------\n"]
        lines.extend(sorted(["%-16s  %4s       %4s       %4s\n"
                             % (m,
                                Vlog.__mfl[m]["console"],
                                Vlog.__mfl[m]["syslog"],
                                Vlog.__mfl[m]["file"]) for m in Vlog.__mfl]))
        return ''.join(lines)

    @staticmethod
    def reopen_log_file():
        """Closes and then attempts to re-open the current log file.  (This is
        useful just after log rotation, to ensure that the new log file starts
        being used.)"""

        if Vlog.__log_file:
            logger = logging.getLogger("file")
            logger.removeHandler(Vlog.__file_handler)
            Vlog.__file_handler = logging.FileHandler(Vlog.__log_file)
            logger.addHandler(Vlog.__file_handler)

    @staticmethod
    def _unixctl_vlog_reopen(conn, unused_argv, unused_aux):
        if Vlog.__log_file:
            Vlog.reopen_log_file()
            conn.reply(None)
        else:
            conn.reply("Logging to file not configured")

    @staticmethod
    def _unixctl_vlog_set(conn, argv, unused_aux):
        for arg in argv:
            msg = Vlog.set_levels_from_string(arg)
            if msg:
                conn.reply(msg)
                return
        conn.reply(None)

    @staticmethod
    def _unixctl_vlog_list(conn, unused_argv, unused_aux):
        conn.reply(Vlog.get_levels())

def add_args(parser):
    """Adds vlog related options to 'parser', an ArgumentParser object.  The
    resulting arguments parsed by 'parser' should be passed to handle_args."""

    group = parser.add_argument_group(title="Logging Options")
    group.add_argument("--log-file", nargs="?", const="default",
                       help="Enables logging to a file.  Default log file"
                       " is used if LOG_FILE is omitted.")
    group.add_argument("-v", "--verbose", nargs="*",
                       help="Sets logging levels, see ovs-vswitchd(8)."
                       "  Defaults to dbg.")


def handle_args(args):
    """ Handles command line arguments ('args') parsed by an ArgumentParser.
    The ArgumentParser should have been primed by add_args().  Also takes care
    of initializing the Vlog module."""

    log_file = args.log_file
    if log_file == "default":
        log_file = "%s/%s.log" % (ovs.dirs.LOGDIR, ovs.util.PROGRAM_NAME)

    if args.verbose is None:
        args.verbose = []
    elif args.verbose == []:
        args.verbose = ["any:any:dbg"]

    for verbose in args.verbose:
        msg = Vlog.set_levels_from_string(verbose)
        if msg:
            ovs.util.ovs_fatal(0, "processing \"%s\": %s" % (verbose, msg))

    Vlog.init(log_file)
