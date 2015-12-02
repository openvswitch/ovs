# Copyright (c) 2015 Nicira, Inc.
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

import argparse
import socket

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import TCPServer


class TCPServerV6(HTTPServer):
    address_family = socket.AF_INET6


def get_ftpd():
    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer

        import logging
        import pyftpdlib.log
        pyftpdlib.log.LEVEL = logging.DEBUG

        class OVSFTPHandler(FTPHandler):
            authorizer = DummyAuthorizer()
            authorizer.add_anonymous("/tmp")
            # Hack around a bug in pyftpdlib, which rejects EPRT
            # connection due to mismatching textual representation of
            # the IPv6 address.
            permit_foreign_addresses = True
        server = [FTPServer, OVSFTPHandler, 21]
    except ImportError:
        server = None
        pass
    return server


def main():
    SERVERS = {
        'http':  [TCPServer,   SimpleHTTPRequestHandler, 80],
        'http6': [TCPServerV6, SimpleHTTPRequestHandler, 80],
    }

    ftpd = get_ftpd()
    if ftpd is not None:
        SERVERS['ftp'] = ftpd

    protocols = [srv for srv in SERVERS]
    parser = argparse.ArgumentParser(
            description='Run basic application servers.')
    parser.add_argument('proto', default='http', nargs='?',
            help='protocol to serve (%s)' % protocols)
    args = parser.parse_args()

    if args.proto not in SERVERS:
        parser.print_help()
        exit(1)

    constructor = SERVERS[args.proto][0]
    handler = SERVERS[args.proto][1]
    port = SERVERS[args.proto][2]
    srv = constructor(('', port), handler)
    srv.serve_forever()


if __name__ == '__main__':
    main()
