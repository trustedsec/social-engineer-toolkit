#!/usr/bin/env python
import socket
import os
from socketserver import BaseServer
from http.server import HTTPServer
from http.server import SimpleHTTPRequestHandler
from OpenSSL import SSL


class SecureHTTPServer(HTTPServer):

    def __init__(self, server_address, HandlerClass):
        BaseServer.__init__(self, server_address, HandlerClass)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        # server.pem's location (containing the server private key and
        # the server certificate).
        fpem_priv = 'newreq.pem'  # server
        fpem_cli = 'newcert.pem'  # cli
        ctx.use_privatekey_file(fpem_priv)
        ctx.use_certificate_file(fpem_cli)
        self.socket = SSL.Connection(ctx, socket.socket(self.address_family,
                                                        self.socket_type))
        self.server_bind()
        self.server_activate()

    def shutdown_request(self, request): request.shutdown()


class SecureHTTPRequestHandler(SimpleHTTPRequestHandler):

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)


def main_server(HandlerClass=SecureHTTPRequestHandler,
                ServerClass=SecureHTTPServer):
    server_address = ('', 443)  # (address, port)
    httpd = ServerClass(server_address, HandlerClass)
    sa = httpd.socket.getsockname()
    print("Serving HTTPS on", sa[0], "port", sa[1], "...")

if __name__ == '__main__':
    main_server()
