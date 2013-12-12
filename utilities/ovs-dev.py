#!/usr/bin/python
# Copyright (c) 2013 Nicira, Inc.
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

import optparse
import os
import shutil
import subprocess
import sys
import tempfile

ENV = os.environ
HOME = ENV["HOME"]
OVS_SRC = HOME + "/ovs"
ROOT = HOME + "/root"
BUILD_GCC = OVS_SRC + "/_build-gcc"
BUILD_CLANG = OVS_SRC + "/_build-clang"
PATH = "%(ovs)s/utilities:%(ovs)s/ovsdb:%(ovs)s/vswitchd" % {"ovs": BUILD_GCC}

ENV["CFLAGS"] = "-g -O0"
ENV["PATH"] = PATH + ":" + ENV["PATH"]

options = None
parser = None
commands = []


def _sh(*args, **kwargs):
    print "------> " + " ".join(args)
    shell = len(args) == 1
    if kwargs.get("capture", False):
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, shell=shell)
        return proc.stdout.readlines()
    elif kwargs.get("check", True):
        subprocess.check_call(args, shell=shell)
    else:
        subprocess.call(args, shell=shell)


def uname():
    return _sh("uname", "-r", capture=True)[0].strip()


def conf():
    tag()

    try:
        os.remove(OVS_SRC + "/Makefile")
    except OSError:
        pass

    configure = ["../configure", "--prefix=" + ROOT, "--localstatedir=" + ROOT,
                 "--with-logdir=%s/log" % ROOT, "--with-rundir=%s/run" % ROOT,
                 "--with-linux=/lib/modules/%s/build" % uname(),
                 "--with-dbdir=" + ROOT]

    if options.werror:
        configure.append("--enable-Werror")

    if options.cache_time:
        configure.append("--enable-cache-time")

    if options.mandir:
        configure.append("--mandir=" + options.mandir)

    _sh("./boot.sh")

    try:
        os.mkdir(BUILD_GCC)
    except OSError:
        pass # Directory exists.

    os.chdir(BUILD_GCC)
    _sh(*configure)

    try:
        _sh("clang --version", check=True)
        clang = True
    except subprocess.CalledProcessError:
        clang = False

    try:
        _sh("sparse --version", check=True)
        sparse = True
    except subprocess.CalledProcessError:
        sparse = False

    if clang:
        try:
            os.mkdir(BUILD_CLANG)
        except OSError:
            pass # Directory exists.

        ENV["CC"] = "clang"
        os.chdir(BUILD_CLANG)
        _sh(*configure)

    if sparse:
        c1 = "C=1"
    else:
        c1 = ""

    os.chdir(OVS_SRC)

    make_str = "\t$(MAKE) -C %s $@\n"

    mf = open(OVS_SRC + "/Makefile", "w")
    mf.write("all:\n%:\n")
    if clang:
        mf.write(make_str % BUILD_CLANG)
    mf.write("\t$(MAKE) -C %s %s $@\n" % (BUILD_GCC, c1))
    mf.write("\ncheck:\n")
    mf.write(make_str % BUILD_GCC)
    mf.close()
commands.append(conf)


def make(args=""):
    make = "make -s -j 8 " + args
    _sh(make)
commands.append(make)


def check():
    make("check")
commands.append(check)


def tag():
    ctags = ['ctags', '-R', '-f', '.tags']

    try:
        _sh(*(ctags + ['--exclude="datapath/"']))
    except:
        try:
            _sh(*ctags)  # Some versions of ctags don't have --exclude
        except:
            pass

    try:
        _sh('cscope', '-R', '-b')
    except:
        pass
commands.append(tag)


def kill():
    for proc in ["ovs-vswitchd", "ovsdb-server"]:
        if os.path.exists("%s/run/openvswitch/%s.pid" % (ROOT, proc)):
            _sh("ovs-appctl", "-t", proc, "exit", check=False)
            time.sleep(.1)
        _sh("sudo", "killall", "-q", "-2", proc, check=False)
commands.append(kill)


def reset():
    kill()
    if os.path.exists(ROOT):
        shutil.rmtree(ROOT)
    for dp in _sh("ovs-dpctl dump-dps", capture=True):
        _sh("ovs-dpctl", "del-dp", dp.strip())
commands.append(reset)


def run():
    kill()
    for d in ["log", "run"]:
        d = "%s/%s" % (ROOT, d)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    pki_dir = ROOT + "/pki"
    if not os.path.exists(pki_dir):
        os.mkdir(pki_dir)
        os.chdir(pki_dir)
        _sh("ovs-pki init")
        _sh("ovs-pki req+sign ovsclient")
        os.chdir(OVS_SRC)

    if not os.path.exists(ROOT + "/conf.db"):
        _sh("ovsdb-tool", "create", ROOT + "/conf.db",
            OVS_SRC + "/vswitchd/vswitch.ovsschema")

    opts = ["--pidfile", "--log-file", "--enable-dummy"]

    _sh(*(["ovsdb-server",
           "--remote=punix:%s/run/db.sock" % ROOT,
           "--remote=db:Open_vSwitch,Open_vSwitch,manager_options",
           "--private-key=db:Open_vSwitch,SSL,private_key",
           "--certificate=db:Open_vSwitch,SSL,certificate",
           "--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert",
           "--detach", "-vconsole:off"] + opts))

    _sh("ovs-vsctl --no-wait --bootstrap set-ssl %s/ovsclient-privkey.pem" \
        " %s/ovsclient-cert.pem %s/vswitchd.cacert"
        % (pki_dir, pki_dir, pki_dir))
    version = _sh("ovs-vsctl --no-wait --version", capture=True)
    version = version[0].strip().split()[3]
    root_uuid = _sh("ovs-vsctl --no-wait --bare list Open_vSwitch",
                    capture=True)[0].strip()
    _sh("ovs-vsctl --no-wait set Open_vSwitch %s ovs_version=%s"
        % (root_uuid, version))

    cmd = [BUILD_GCC + "/vswitchd/ovs-vswitchd"]
    if options.gdb:
        cmd = ["gdb", "--args"] + cmd
    elif options.valgrind:
        cmd = ["valgrind", "--track-origins=yes", "--leak-check=full",
               "--suppressions=%s/tests/glibc.supp" % OVS_SRC,
               "--suppressions=%s/tests/openssl.supp" % OVS_SRC] + cmd
    else:
        cmd = ["sudo"] + cmd
        opts = opts + ["-vconsole:off", "--detach"]
    _sh(*(cmd + opts))
commands.append(run)


def modinst():
    if not os.path.exists("/lib/modules"):
        print "Missing modules directory.  Is this a Linux system?"
        sys.exit(1)

    try:
        _sh("rmmod", "openvswitch")
    except subprocess.CalledProcessError, e:
        pass  # Module isn't loaded

    try:
        _sh("rm /lib/modules/%s/extra/openvswitch.ko" % uname())
    except subprocess.CalledProcessError, e:
        pass  # Module isn't installed

    conf()
    make()
    make("modules_install")

    _sh("modprobe", "openvswitch")
    _sh("dmesg | grep openvswitch | tail -1")
commands.append(modinst)


def env():
    print "export PATH=" + ENV["PATH"]
commands.append(env)


def doc():
    parser.print_help()
    print \
"""
This program is designed to help developers build and run Open vSwitch without
necessarily needing to know the gory details. Given some basic requirements
(described below), it can be used to build and run Open vSwitch, keeping
runtime files in the user's home directory.

Basic Configuration:
    # This section can be run as a script on ubuntu systems.

    # First install the basic requirements needed to build Open vSwitch.
    sudo apt-get install git build-essential libtool autoconf pkg-config \\
            libssl-dev gdb linux-headers-`uname -r`

    # Next clone the Open vSwitch source.
    git clone git://git.openvswitch.org/openvswitch %(ovs)s

    # Setup environment variables.
    `%(v)s env`

    # Build the switch.
    %(v)s conf make

    # Install the kernel module
    sudo insmod %(ovs)s/datapath/linux/openvswitch.ko

    # Run the switch.
    %(v)s run

Commands:
    conf    - Configure the ovs source.
    make    - Build the source (must have been configured).
    check   - Run the unit tests.
    tag     - Run ctags and cscope over the source.
    kill    - Kill all running instances of ovs.
    reset   - Reset any runtime configuration in %(run)s.
    run     - Run ovs.
    modinst - Build ovs and install the kernel module.
    env     - Print the required path environment variable.
    doc     - Print this message.
""" % {"ovs": OVS_SRC, "v": sys.argv[0], "run": ROOT}
    sys.exit(0)
commands.append(doc)


def main():
    global options
    global parser

    description = "Open vSwitch developer configuration. Try `%prog doc`."
    cmd_names = [c.__name__ for c in commands]
    parser = optparse.OptionParser(usage="usage: %prog"
                                   + " [options] [%s] ..."
                                   % "|".join(cmd_names),
                                   description=description)

    group = optparse.OptionGroup(parser, "conf")
    group.add_option("--disable-Werror", dest="werror", action="store_false",
                     default=True, help="compile without the Werror flag")
    group.add_option("--cache-time", dest="cache_time",
                     action="store_true", help="configure with cached timing")
    group.add_option("--mandir", dest="mandir", metavar="MANDIR",
                     help="configure the man documentation install directory")
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "run")
    group.add_option("-g", "--gdb", dest="gdb", action="store_true",
                     help="run ovs-vswitchd under gdb")
    group.add_option("--valgrind", dest="valgrind", action="store_true",
                     help="run ovs-vswitchd under valgrind")
    parser.add_option_group(group)

    options, args = parser.parse_args()

    for arg in args:
        if arg not in cmd_names:
            print "Unknown argument " + arg
            doc()

    try:
        os.chdir(OVS_SRC)
    except OSError:
        print "Missing %s." % OVS_SRC
        doc()

    for arg in args:
        for cmd in commands:
            if arg == cmd.__name__:
                cmd()


if __name__ == '__main__':
    main()
