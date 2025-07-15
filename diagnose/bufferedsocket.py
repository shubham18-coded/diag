#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# extracted from https://github.com/Gallopsled/pwntools/tree/2.2/pwnlib/tubes/{remote,sock,tube}.py
#
# Copyright (c) 2015 Gallopsled et al.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import errno
import socket
import time
import logging

LOG = logging.getLogger("diagnose.bufferedsocket")
TIMEOUT_DEFAULT = 10


class BufferedSocket(object):
    def __init__(self, sock):
        self.sock = sock
        self.rhost, self.rport = sock.getpeername()
        self.closed = False
        self.buffer = bytearray()

    def close(self):
        if self.closed:
            return

        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RD)
        except IOError as e:
            if e.errno != errno.ENOTCONN:
                raise
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except IOError as e:
            if e.errno != errno.ENOTCONN:
                raise
        self.sock.close()
        LOG.debug("Closed connection to %s:%d", self.rhost, self.rport)

    def get(self, numb=None):
        if numb is None:
            numb = len(self.buffer)
        if len(self.buffer) < numb:
            raise IndexError("requested %d bytes from buffer which only has %d bytes" % (numb, len(self.buffer)))
        data, self.buffer = self.buffer[:numb], self.buffer[numb:]
        return bytes(data)

    def clean(self, timeout=0.05):
        if timeout != 0:
            timeout_old = self.sock.gettimeout()
            self.sock.settimeout(timeout)

            try:
                while True:
                    received = self.recv_raw(4096)
                    if received is None:
                        # recv hit a timeout
                        break

                    self.buffer += received
            finally:
                self.sock.settimeout(timeout_old)

        return self.get()

    def send(self, data):
        try:
            self.sock.sendall(data)
        except IOError as e:
            if e.errno in [errno.EPIPE, errno.ECONNRESET, errno.ECONNREFUSED]:
                self.close()
                raise EOFError
            else:
                raise

    def recv_raw(self, numb):
        while True:
            try:
                data = self.sock.recv(numb)
                break
            except socket.timeout:
                return None
            except IOError as e:
                if e.errno in [errno.ECONNREFUSED, errno.ECONNRESET]:
                    self.close()
                    raise EOFError
                elif e.errno == errno.EINTR:
                    continue
                else:
                    raise

        if data == b"":
            self.close()
            raise EOFError

        return data

    def recvn(self, numb, timeout=TIMEOUT_DEFAULT):
        missingb = numb - len(self.buffer)

        timeout_end = time.time() + timeout
        timeout_old = self.sock.gettimeout()

        try:
            while missingb > 0:
                timeout_diff = timeout_end - time.time()
                if timeout_diff <= 0:
                    # no time left
                    return b""

                self.sock.settimeout(timeout_diff)
                received = self.recv_raw(4096)
                if received is None:
                    # recv hit a timeout
                    return b""

                self.buffer += received
                missingb = numb - len(self.buffer)
        finally:
            if not self.closed:
                self.sock.settimeout(timeout_old)

        return self.get(numb)

    def recvuntil(self, delim, timeout=TIMEOUT_DEFAULT):
        timeout_end = time.time() + timeout
        timeout_old = self.sock.gettimeout()

        try:
            found = self.buffer.index(delim)
        except ValueError:
            found = None
        try:
            while found is None:
                timeout_diff = timeout_end - time.time()
                if timeout_diff <= 0:
                    # no time left
                    return b""

                self.sock.settimeout(timeout_diff)
                received = self.recv_raw(4096)
                if received is None:
                    # recv hit a timeout
                    return b""

                self.buffer += received
                try:
                    found = self.buffer.index(delim)
                except ValueError:
                    found = None
        finally:
            self.sock.settimeout(timeout_old)

        return self.get(found + len(delim))


def binary_ip(host):
    return socket.inet_aton(socket.gethostbyname(host))
