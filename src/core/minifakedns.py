#!/usr/bin/env python
"""
SET core PyFakeMiniDNS server implementation.

Slightly modified implementation of Francisco Santos's PyfakeminiDNS
script designed to run as a thread and handle various additional
system configuration tasks, if necessary in the running environment,
along with a few implementation considerations specifically for SET.
"""

import os
import socket
import subprocess
import sys
import threading

# We need this module variable so the helper functions can be called
# from outside of this module, e.g., during SET startup and cleanup.
dns_server_thread = None

def start_dns_server():
    """
    Helper function, intended to be called from other modules.
    """
    global dns_server_thread
    dns_server_thread = MiniFakeDNS(kwargs={'port': 53, 'ip': '1.2.3.4'})
    dns_server_thread.start()

def stop_dns_server():
    """
    Helper function, intended to be called from other modules.
    """
    dns_server_thread.stop()
    dns_server_thread.join()
    dns_server_thread.cleanup()

class DNSQuery:
    """
     A DNS query (that can be parsed as binary data).

     See original for reference, but note there have been changes:
     https://code.activestate.com/recipes/491264-mini-fake-dns-server/

    """

    def __init__(self, data):
        self.data = data
        self.dominio = ''

        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.dominio += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])

    def respuesta(self, ip):
        packet = ''
        if self.dominio:
            packet += self.data[:2] + "\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00' # Questions and Answers Counts
            packet += self.data[12:]                                       # Original Domain Name Question
            packet += '\xc0\x0c'                                           # Pointer to domain name
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' # Response type, ttl and resource data length -> 4 bytes
            packet += str.join('', [chr(int(x)) for x in ip.split('.')])   # 4bytes of IP
        return packet

class MiniFakeDNS(threading.Thread):
    """
    The MiniFakeDNS server, written to be run as a Python Thread.
    """
    def __init__(self, group=None, target=None, name=None,
                       args=(), kwargs=None):
        super(MiniFakeDNS, self).__init__(
                group=group, target=target, name=name)
        self.args = args
        self.kwargs = kwargs

        # The IPs address we will respond with.
        self.ip = kwargs['ip']

        # The port number we will attempt to bind to. Default is 53.
        self.port = kwargs['port']

        # Remember which configuration we usurped, if any. Used to cleanup.
        self.cede_configuration = None

        # A flag to indicate that the thread should exit.
        self.stop_flag = False

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udps:
            udps.setblocking(False)
            try:
                udps.bind(('', self.port))
            except OSError as e:
                if 'Address already in use' == e.strerror and os.path.exists('/etc/resolv.conf'):
                    # We can't listen on port 53 because something else got
                    # there before we did. It's probably systemd-resolved's
                    # DNS stub resolver, but since we are probably running as
                    # the `root` user, we can fix this ourselves.
                    if 'stub-resolv.conf' in os.path.realpath('/etc/resolv.conf'):
                        self.usurp_systemd_resolved()
                        self.cede_configuration = self.cede_to_systemd_resolved
                    # Try binding again, now that the port might be available.
                    udps.bind(('', self.port))
            while not self.stop_flag:
                try:
                    data, addr = udps.recvfrom(1024)
                    p = DNSQuery(data)
                    udps.sendto(p.respuesta(self.ip), addr)
                except BlockingIOError:
                    pass
            print("Exiting the DNS Server..")
        sys.exit()

    def cleanup(self):
        if self.cede_configuration is not None:
            self.cede_configuration()

    def stop(self):
        """
        Signals to the DNS server thread to stop.
        """
        self.stop_flag = True

    def usurp_systemd_resolved(self):
        """
        Helper function to get systemd-resolved out of the way when it
        is listening on 127.0.0.1:53 and we are trying to run SET's
        own DNS server.
        """
        try:
            os.mkdir('/etc/systemd/resolved.conf.d')
        except (OSError, FileExistsError):
            pass
        with open('/etc/systemd/resolved.conf.d/99-setoolkit-dns.conf', 'w') as f:
            f.write("[Resolve]\nDNS=9.9.9.9\nDNSStubListener=no")
        os.rename('/etc/resolv.conf', '/etc/resolv.conf.original')
        os.symlink('/run/systemd/resolve/resolv.conf', '/etc/resolv.conf')
        subprocess.call(['systemctl', 'restart', 'systemd-resolved.service'])

    def cede_to_systemd_resolved(self):
        """
        Helper function to cede system configuration back to systemd-resolved
        after we have usurped control over DNS configuration away from it.
        """
        os.remove('/etc/systemd/resolved.conf.d/99-setoolkit-dns.conf')
        os.remove('/etc/resolv.conf')
        os.rename('/etc/resolv.conf.original', '/etc/resolv.conf')
        subprocess.call(['systemctl', 'restart', 'systemd-resolved.service'])

