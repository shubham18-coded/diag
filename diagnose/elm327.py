#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging

import socket
import threading
import time

import can

from diagnose import bufferedsocket
from diagnose.can import CANDiagnoseAdapter
from diagnose.tools import enhex, unhex

LOG = logging.getLogger("diagnose.elm327")
CAN_MASK = 0x7FF

CONNECTION_TYPE = "elm327"


def insert_argument_parser(parser):
    parser = parser.add_parser(CONNECTION_TYPE, help="connect via elm327 dongle")
    parser.set_defaults(setup_connection=setup_connection)
    parser.add_argument("--host", default="192.168.0.10", help="dongle host")
    parser.add_argument("-p", "--port", default="35000", type=int, help="dongle port")
    parser.add_argument("--normal", action="store_true", help="use normal addressing instead of extended addressing")


class NoPrompt(RuntimeError):
    pass


# FIXME not thread safe!
# TODO works on carly, does not yet work on other dongle!
PROMPT = b"\r>"
OK = b"OK\r"


class CanAdapter(object):
    def __init__(self, sock):
        self.sock = sock
        self.last_sh = None

        self.condition = threading.Condition()
        time.sleep(0.5)
        self.sock.clean()
        self.sock.send(b"\r\n")

        with self.condition:
            for h in (b"Z", b"E0", b"S1", b"V1", b"H1", b"SP 6", b"CAF0", b"CFC0", b"CM 600", b"CF 600"):
                self.wait_prompt()
                self.sock.send(b"AT %s\r\n" % h)
                if self.sock.recvuntil(OK) != OK:
                    raise ValueError("header %r not ok" % h)
            time.sleep(0.2)

    def wait_prompt(self, timeout=1):
        if not self.sock.recvuntil(PROMPT, timeout=timeout).endswith(PROMPT):
            raise NoPrompt()

    def set_filters(self, can_filters=None):
        if not can_filters:
            with self.condition:
                self.wait_prompt()
                self.sock.send(b"AT CRA\r\n")
                if self.sock.recvuntil(OK) != OK:
                    raise ValueError("resetting filters not ok")
        elif len(can_filters) == 1:
            can_id = can_filters[0]["can_id"]
            can_mask = can_filters[0]["can_mask"]
            with self.condition:
                for h in (b"CRA", b"CM 7FF", b"CF %03X" % can_id, b"CM %03X" % can_mask):
                    self.wait_prompt()
                    self.sock.send(b"AT %s\r\n" % h)
                    if self.sock.recvuntil(OK) != OK:
                        raise ValueError("header %r not ok" % h)
        else:
            raise NotImplementedError("ELM327 can only handle one HW-filter")

    def recv(self, timeout=None):
        with self.condition:
            while True:
                LOG.info("receiving...")
                b = self.sock.recvuntil(b"\r", timeout=timeout or 0.5)
                LOG.info("received: %r", b)
                if b == b"\r" or b == b">\r" or b == "?\r":
                    continue
                if b == b"" and timeout is None:
                    self.condition.wait()
                break
        if b.startswith(">"):
            b = b[1:]
        if b == b"":
            return None
        if b == "STOPPED\r":
            return None
        if b == "NO DATA\r":
            return None
        LOG.info("received: %r", b)
        try:
            hdr, payload = b.split(" ", 1)
            canid = int(hdr, 16)
        except Exception as error:
            LOG.error("buffer: %r", b)
            LOG.error("remaining buffer: %r", self.sock.buffer)
            raise error
        return can.Message(arbitration_id=canid, data=unhex(payload[:-1]))

    def __iter__(self):
        while True:
            msg = self.recv()
            if msg:
                yield msg

    def send(self, msg):
        with self.condition:
            self.wait_prompt()
            if self.last_sh != msg.arbitration_id:
                LOG.info("switching receiver id to: %03x", msg.arbitration_id)
                self.sock.send("AT SH %03X\r\n" % msg.arbitration_id)
                time.sleep(0.2)
                b = self.sock.recvuntil(OK)
                if b == b"":
                    raise ValueError("header 'SH %03X' not ok" % msg.arbitration_id)
                self.last_sh = msg.arbitration_id
                self.wait_prompt()
            LOG.info("sending: %s", enhex(str(msg.data)).upper())
            self.sock.send(enhex(str(msg.data)).upper().encode("ascii") + "\r\n")
            self.condition.notify()
            LOG.info("done sending")


class ELM327DiagnoseAdapter(CANDiagnoseAdapter):
    def __init__(self, host, port, extended_addressing=True):
        super(ELM327DiagnoseAdapter, self).__init__(extended_addressing=extended_addressing, buffer_size=9)

        self.is_alive = True
        self.socket = None
        self.host = host
        self.port = port

    def __enter__(self):
        sock = socket.create_connection((self.host, self.port), timeout=1)
        self.socket = bufferedsocket.BufferedSocket(sock)
        self.bus = CanAdapter(self.socket)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.is_alive = False

        if self.socket:
            LOG.info("[+] closing the elm327 dongle connection")
            self.socket.close()
            self.socket = None

    def process_tp(self, *args, **kwargs):
        time.sleep(0.1)
        return super(ELM327DiagnoseAdapter, self).process_tp(*args, **kwargs)


def setup_connection(args):
    return ELM327DiagnoseAdapter(args.host, args.port, not args.normal)
