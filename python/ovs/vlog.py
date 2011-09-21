
# Copyright (c) 2011 Nicira Networks
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
import socket
import sys

import ovs.dirs
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

        now = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        message = ("%s|%s|%s|%s|%s"
                   % (now, Vlog.__msg_num, self.name, level, message))

        level = LEVELS.get(level.lower(), logging.DEBUG)
        Vlog.__msg_num += 1

        for f, f_level in Vlog.__mfl[self.name].iteritems():
            f_level = LEVELS.get(f_level, logging.CRITICAL)
            if level >= f_level:
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
                elif f == "file" and log_file:
                    logger.addHandler(logging.FileHandler(log_file))
            except (IOError, socket.error):
                logger.setLevel(logging.CRITICAL)

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


def add_args(parser):
    """Adds vlog related options to 'parser', an ArgumentParser object.  The
    resulting arguments parsed by 'parser' should be passed to handle_args."""

    group = parser.add_argument_group(title="Logging Options")
    group.add_argument("--log-file", nargs="?", const="default",
                       help="Enables logging to a file.  Default log file"
                       " is used if LOG_FILE is omitted.")
    group.add_argument("-v", "--verbose", nargs="*",
                       help="Sets logging levels, see ovs-vswitchd(8)."
                       "  Defaults to ANY:ANY:dbg.")


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
        args = verbose.split(':')

        if len(args) >= 3:
            level = args[2]
        else:
            level = "dbg"

        if len(args) >= 2:
            facility = args[1]
        else:
            facility = "any"

        if len(args) >= 1:
            module = args[0]
        else:
            module = "any"

        Vlog.set_level(module, facility, level)

    Vlog.init(log_file)
