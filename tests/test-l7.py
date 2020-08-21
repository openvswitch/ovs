#!/usr/bin/env python3
# Copyright (c) 2015, 2016, 2020 Nicira, Inc.
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

try:  # Python 2.7
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from SocketServer import TCPServer
except:
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    from socketserver import TCPServer


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


def get_tftpd():
    try:
        from tftpy import TftpServer, TftpShared

        class OVSTFTPServer(TftpServer):
            def __init__(self, listen, handler=None):
                (ip, port) = listen
                self.ip = ip
                self.port = port
                TftpServer.__init__(self, tftproot='./')

            def serve_forever(self):
                self.listen(self.ip, self.port)
        server = [OVSTFTPServer, None, TftpShared.DEF_TFTP_PORT]
    except (ImportError, SyntaxError):
        server = None
        pass
    return server


def main():
    SERVERS = {
        'http': [TCPServer, SimpleHTTPRequestHandler, 80],
        'http6': [TCPServerV6, SimpleHTTPRequestHandler, 80],
        'ftp': get_ftpd(),
        'tftp': get_tftpd(),
    }

    protocols = [srv for srv in SERVERS if SERVERS[srv] is not None]
    parser = argparse.ArgumentParser(
        description='Run basic application servers.')
    parser.add_argument('proto', default='http', nargs='?',
                        help='protocol to serve (%s)' % protocols)
    args = parser.parse_args()

    if args.proto not in protocols:
        parser.print_help()
        exit(1)

    constructor = SERVERS[args.proto][0]
    handler = SERVERS[args.proto][1]
    port = SERVERS[args.proto][2]
    srv = constructor(('', port), handler)
    srv.serve_forever()


if __name__ == '__main__':
    main()
