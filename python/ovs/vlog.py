
# Copyright (c) 2011, 2012, 2013, 2015, 2016 Nicira, Inc.
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
import os
import re
import socket
import sys
import threading

import ovs.dirs
import ovs.unixctl
import ovs.util

import six
from six.moves import range

DESTINATIONS = {"console": "info", "file": "info", "syslog": "info"}
PATTERNS = {
    "console": "%D{%Y-%m-%dT%H:%M:%SZ}|%05N|%c%T|%p|%m",
    "file": "%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m",
    "syslog": "ovs|%05N|%c%T|%p|%m",
}
LEVELS = {
    "dbg": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "err": logging.ERROR,
    "emer": logging.CRITICAL,
    "off": logging.CRITICAL
}
FACILITIES = ['auth', 'authpriv', 'cron', 'daemon', 'ftp', 'kern', 'lpr',
              'mail', 'news', 'syslog', 'user', 'uucp', 'local0', 'local1',
              'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
syslog_facility = "daemon"
syslog_handler = ''


def get_level(level_str):
    return LEVELS.get(level_str.lower())


class Vlog(object):
    __inited = False
    __msg_num = 0
    __start_time = 0
    __mfl = {}  # Module -> destination -> level
    __log_file = None
    __file_handler = None
    __log_patterns = PATTERNS

    def __init__(self, name):
        """Creates a new Vlog object representing a module called 'name'.  The
        created Vlog object will do nothing until the Vlog.init() static method
        is called.  Once called, no more Vlog objects may be created."""

        assert not Vlog.__inited
        self.name = name.lower()
        if name not in Vlog.__mfl:
            Vlog.__mfl[self.name] = DESTINATIONS.copy()

    def __log(self, level, message, **kwargs):
        if not Vlog.__inited:
            return

        level_num = LEVELS.get(level.lower(), logging.DEBUG)
        msg_num = Vlog.__msg_num
        Vlog.__msg_num += 1

        for f, f_level in six.iteritems(Vlog.__mfl[self.name]):
            f_level = LEVELS.get(f_level, logging.CRITICAL)
            if level_num >= f_level:
                msg = self._build_message(message, f, level, msg_num)
                logging.getLogger(f).log(level_num, msg, **kwargs)

    def _build_message(self, message, destination, level, msg_num):
        pattern = self.__log_patterns[destination]
        tmp = pattern

        tmp = self._format_time(tmp)

        matches = re.findall("(%-?[0]?[0-9]?[AcmNnpPrtT])", tmp)
        for m in matches:
            if "A" in m:
                tmp = self._format_field(tmp, m, ovs.util.PROGRAM_NAME)
            elif "c" in m:
                tmp = self._format_field(tmp, m, self.name)
            elif "m" in m:
                tmp = self._format_field(tmp, m, message)
            elif "N" in m:
                tmp = self._format_field(tmp, m, str(msg_num))
            elif "n" in m:
                tmp = re.sub(m, "\n", tmp)
            elif "p" in m:
                tmp = self._format_field(tmp, m, level.upper())
            elif "P" in m:
                self._format_field(tmp, m, str(os.getpid()))
            elif "r" in m:
                now = datetime.datetime.utcnow()
                delta = now - self.__start_time
                ms = delta.microseconds / 1000
                tmp = self._format_field(tmp, m, str(ms))
            elif "t" in m:
                subprogram = threading.currentThread().getName()
                if subprogram == "MainThread":
                    subprogram = "main"
                tmp = self._format_field(tmp, m, subprogram)
            elif "T" in m:
                subprogram = threading.currentThread().getName()
                if not subprogram == "MainThread":
                    subprogram = "({})".format(subprogram)
                else:
                    subprogram = ""
                tmp = self._format_field(tmp, m, subprogram)
        return tmp.strip()

    def _format_field(self, tmp, match, replace):
        formatting = re.compile("^%(0)?([1-9])?")
        matches = formatting.match(match)
        # Do we need to apply padding?
        if not matches.group(1) and replace != "":
            replace = replace.center(len(replace) + 2)
        # Does the field have a minimum width
        if matches.group(2):
            min_width = int(matches.group(2))
            if len(replace) < min_width:
                replace = replace.center(min_width)
        return re.sub(match, replace, tmp)

    def _format_time(self, tmp):
        date_regex = re.compile('(%(0?[1-9]?[dD])(\{(.*)\})?)')
        match = date_regex.search(tmp)

        if match is None:
            return tmp

        # UTC date or Local TZ?
        if match.group(2) == "d":
            now = datetime.datetime.now()
        elif match.group(2) == "D":
            now = datetime.datetime.utcnow()

        # Custom format or ISO format?
        if match.group(3):
            time = datetime.date.strftime(now, match.group(4))
            try:
                i = len(re.search("#+", match.group(4)).group(0))
                msec = '{0:0>{i}.{i}}'.format(str(now.microsecond / 1000), i=i)
                time = re.sub('#+', msec, time)
            except AttributeError:
                pass
        else:
            time = datetime.datetime.isoformat(now.replace(microsecond=0))

        return self._format_field(tmp, match.group(1), time)

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
        for f, f_level in six.iteritems(Vlog.__mfl[self.name]):
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
        Vlog.__start_time = datetime.datetime.utcnow()
        logging.raiseExceptions = False
        Vlog.__log_file = log_file
        for f in DESTINATIONS:
            logger = logging.getLogger(f)
            logger.setLevel(logging.DEBUG)

            try:
                if f == "console":
                    logger.addHandler(logging.StreamHandler(sys.stderr))
                elif f == "syslog":
                    Vlog.add_syslog_handler()
                elif f == "file" and Vlog.__log_file:
                    Vlog.__file_handler = logging.FileHandler(Vlog.__log_file)
                    logger.addHandler(Vlog.__file_handler)
            except (IOError, socket.error):
                logger.setLevel(logging.CRITICAL)

        ovs.unixctl.command_register("vlog/reopen", "", 0, 0,
                                     Vlog._unixctl_vlog_reopen, None)
        ovs.unixctl.command_register("vlog/close", "", 0, 0,
                                     Vlog._unixctl_vlog_close, None)
        try:
            # Windows limitation on Python 2, sys.maxsize is a long number
            # on 64 bits environments, while sys.maxint is the maximum int
            # number. Python 3 works as expected.
            maxsize_int = sys.maxint
        except AttributeError:
            maxsize_int = sys.maxsize
        ovs.unixctl.command_register("vlog/set", "spec", 1, maxsize_int,
                                     Vlog._unixctl_vlog_set, None)
        ovs.unixctl.command_register("vlog/list", "", 0, 0,
                                     Vlog._unixctl_vlog_list, None)

    @staticmethod
    def set_level(module, destination, level):
        """ Sets the log level of the 'module'-'destination' tuple to 'level'.
        All three arguments are strings which are interpreted the same as
        arguments to the --verbose flag.  Should be called after all Vlog
        objects have already been created."""

        module = module.lower()
        destination = destination.lower()
        level = level.lower()

        if destination != "any" and destination not in DESTINATIONS:
            return

        if module != "any" and module not in Vlog.__mfl:
            return

        if level not in LEVELS:
            return

        if module == "any":
            modules = list(Vlog.__mfl.keys())
        else:
            modules = [module]

        if destination == "any":
            destinations = list(DESTINATIONS.keys())
        else:
            destinations = [destination]

        for m in modules:
            for f in destinations:
                Vlog.__mfl[m][f] = level

    @staticmethod
    def set_pattern(destination, pattern):
        """ Sets the log pattern of the 'destination' to 'pattern' """
        destination = destination.lower()
        Vlog.__log_patterns[destination] = pattern

    @staticmethod
    def add_syslog_handler(facility=None):
        global syslog_facility, syslog_handler

        # If handler is already added and there is no change in 'facility',
        # there is nothing to do.
        if (not facility or facility == syslog_facility) and syslog_handler:
            return

        logger = logging.getLogger('syslog')
        # If there is no infrastructure to support python syslog, disable
        # the logger to avoid repeated errors.
        if not os.path.exists("/dev/log"):
            logger.disabled = True
            return

        if syslog_handler:
            logger.removeHandler(syslog_handler)

        if facility:
            syslog_facility = facility

        syslog_handler = logging.handlers.SysLogHandler(address="/dev/log",
                                                    facility=syslog_facility)
        logger.addHandler(syslog_handler)
        return

    @staticmethod
    def set_levels_from_string(s):
        module = None
        level = None
        destination = None

        words = re.split('[ :]', s)
        if words[0] == "pattern":
            try:
                if words[1] in DESTINATIONS and words[2]:
                    segments = [words[i] for i in range(2, len(words))]
                    pattern = "".join(segments)
                    Vlog.set_pattern(words[1], pattern)
                    return
                else:
                    return "Destination %s does not exist" % words[1]
            except IndexError:
                return "Please supply a valid pattern and destination"
        elif words[0] == "FACILITY":
            if words[1] in FACILITIES:
                Vlog.add_syslog_handler(words[1])
                return
            else:
                return "Facility %s is invalid" % words[1]

        for word in [w.lower() for w in words]:
            if word == "any":
                pass
            elif word in DESTINATIONS:
                if destination:
                    return "cannot specify multiple destinations"
                destination = word
            elif word in LEVELS:
                if level:
                    return "cannot specify multiple levels"
                level = word
            elif word in Vlog.__mfl:
                if module:
                    return "cannot specify multiple modules"
                module = word
            else:
                return "no destination, level, or module \"%s\"" % word

        Vlog.set_level(module or "any", destination or "any", level or "any")

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
    def close_log_file():
        """Closes the current log file. (This is useful on Windows, to ensure
        that a reference to the file is not kept by the daemon in case of
        detach.)"""
        if Vlog.__log_file:
            logger = logging.getLogger("file")
            logger.removeHandler(Vlog.__file_handler)
            Vlog.__file_handler.close()

    @staticmethod
    def _unixctl_vlog_reopen(conn, unused_argv, unused_aux):
        if Vlog.__log_file:
            Vlog.reopen_log_file()
            conn.reply(None)
        else:
            conn.reply("Logging to file not configured")

    @staticmethod
    def _unixctl_vlog_close(conn, unused_argv, unused_aux):
        if Vlog.__log_file:
            if sys.platform != 'win32':
                logger = logging.getLogger("file")
                logger.removeHandler(Vlog.__file_handler)
            else:
                Vlog.close_log_file()
        conn.reply(None)

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
