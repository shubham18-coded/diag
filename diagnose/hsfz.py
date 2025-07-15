#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import abc
import argparse
import logging
import socket
import struct
import threading

import six
from six.moves import socketserver, queue

from diagnose import uds, bufferedsocket
from diagnose.tools import EnumMeta, enhex, clock

LOG = logging.getLogger("diagnose.hsfz")

HSFZ_CONNECTION_TYPE = "hsfz"
HSFZ_DIAG_DEFAULT_PORT = 6801
ZGW_IDENT_AUTO = "AUTO"


def insert_argument_parser(parser):
    hsfz_parser = parser.add_parser(HSFZ_CONNECTION_TYPE, help="connect via Ethernet/HSFZ")
    hsfz_parser.set_defaults(setup_connection=setup_connection)
    hsfz_parser.add_argument("--host", default=ZGW_IDENT_AUTO, help="diagnose server host")
    hsfz_parser.add_argument("--broadcast", default="169.254.255.255", help="ZGW identification broadcast address")
    hsfz_parser.add_argument("-p", "--port", default=HSFZ_DIAG_DEFAULT_PORT, type=int, help="diagnose server port")


class HsfzError(uds.TransportProtocolError):
    def __init__(self, code, message):
        super(HsfzError, self).__init__()
        self._code = code
        self._message = message

    def __repr__(self):
        return "<HsfzError(%r, %s)>" % (self._code, self._message)

    def __str__(self):
        return self.__repr__()


class DiagnoseConnection(six.with_metaclass(abc.ABCMeta, threading.Thread)):
    @abc.abstractmethod
    def run(self):
        pass

    @abc.abstractmethod
    def shutdown(self):
        pass

    @abc.abstractmethod
    def request_new_connection(self):
        pass


class HSFZDiagnoseServer(threading.Thread, socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, bind_address, adapter):
        threading.Thread.__init__(self, name="HSFZDiagnoseServer")
        socketserver.TCPServer.__init__(self, bind_address, None)
        self.adapter = adapter
        self.connection_request = threading.Event()
        self.__shutdown_request = False

    def finish_request(self, request, client_address):
        self.connection_request.clear()
        self.adapter.new_connection(request)
        # keep this connection alive until the diagnosis session requests a new connection
        while not self.__shutdown_request:
            self.connection_request.wait(1)
            if self.connection_request.is_set():
                break
        LOG.info("connection done")

    def run(self):
        self.serve_forever()

    def shutdown(self):
        self.__shutdown_request = True
        socketserver.TCPServer.shutdown(self)

    def request_new_connection(self):
        LOG.info("new connection requested")
        self.connection_request.set()


class HSFZDiagnoseClient(threading.Thread):
    def __init__(self, server_addr, adapter):
        threading.Thread.__init__(self, name="HSFZDiagnoseClient")

        self.server_address = server_addr
        self.adapter = adapter

        self.connection_request = threading.Event()
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False

    def run(self):
        self.__is_shut_down.clear()
        self.connection_request.set()
        try:
            while not self.__shutdown_request:
                self.connection_request.wait(1)
                if self.connection_request.is_set():
                    try:
                        sock = socket.create_connection(self.server_address, timeout=1)
                    except (socket.timeout, ConnectionRefusedError):
                        continue
                    else:
                        self.connection_request.clear()
                        self.adapter.new_connection(sock)
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def shutdown(self):
        self.__shutdown_request = True
        self.__is_shut_down.wait()

    def request_new_connection(self):
        LOG.info("new connection requested")
        self.connection_request.set()


class Kontrollword(six.with_metaclass(EnumMeta, object)):
    default = "undefined"
    value_table = {
        b"\x00\x01": "DIAGREQ",
        b"\x00\x02": "ACK",
        b"\x00\x10": "TERM15",
        b"\x00\x11": "IDENT",
        b"\x00\x12": "ALIVECHECK",
        b"\x00\x13": "STATUS",
        b"\x00\x40": "ERROR_INCORRECT_TESTER_ADDR",
        b"\x00\x41": "ERROR_INCORRECT_KONTROLLWORD",
        b"\x00\x42": "ERROR_INCORRECT_FORMAT",
        b"\x00\x43": "ERROR_INCORRECT_DESTINATION_ADDR",
        b"\x00\x44": "ERROR_MESSAGE_TOO_LARGE",
        b"\x00\x45": "ERROR_DIAG_APPLICATION_NOT_READY",
        b"\x00\xff": "ERROR_OUT_OF_MEMORY",
    }


class Timeout(Exception):
    pass


class HSFZDiagnoseAdapter(uds.DiagnoseAdapter):
    def __init__(self, host, port):
        self.is_alive = True
        self.socket = None

        self.host = host
        self.port = port

        self.connection_condition = threading.Condition()
        self.connection = None

    def get_default_tester_address(self):
        return 0xF4

    def __enter__(self):
        self.connection = self.start_connection(self.host, self.port)
        self.connection.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.is_alive = False

        # then we need to close the active tube (i.e., pwnlib socket) before stopping the
        # socketserver
        if self.socket:
            with self.connection_condition:
                LOG.debug("[+] closing the HSFZ connection")
                self.socket.close()
                self.socket = None

        # last we kill the HSFZ server/client so no new uds are created
        self.connection.shutdown()

    def wait_for_connection(self, timeout=30):
        t_start = clock()
        t_end = t_start + timeout
        timeout_expired = True
        with self.connection_condition:
            while clock() < t_end:
                if self.socket:
                    timeout_expired = False
                    break
                self.connection_condition.wait(0.05)

                if not self.is_alive or not self.connection.is_alive():
                    raise RuntimeError("connector died")
        if timeout_expired:
            LOG.debug("Timeout of %s seconds expired while waiting for connection", timeout)
            raise RuntimeError("Failed to establish connection")

    def start_connection(self, host, port):
        return HSFZDiagnoseClient((host, port), self)

    def new_connection(self, diagsocket):
        with self.connection_condition:
            LOG.debug("[+] UDS connection established")
            self.socket = bufferedsocket.BufferedSocket(diagsocket)
            self.connection_condition.notify()

    def send_request(self, destaddr, payload, testaddr, txack_max):
        hdr = struct.pack(
            "!I2sBB",
            len(payload) + 2,  # total length
            Kontrollword.DIAGREQ.value(),
            testaddr,
            destaddr,  # destination address = ZGW
        )
        if isinstance(payload, six.string_types):
            payload = payload.encode()
        msg = hdr + payload

        LOG.debug("request : %s", enhex(msg))

        with self.connection_condition:
            bufferedpacket = self.read_hsfz_packet(testaddr=testaddr, timeout=-1)
            if bufferedpacket:
                # got something else, log it, discard and keep looking for ack
                LOG.warning(
                    "unexpected HSFZ packet received before sending: %r / %s",
                    bufferedpacket[0],
                    enhex(bufferedpacket[1]),
                )

            try:
                self.socket.send(msg)
            except EOFError:
                self.socket = None
                raise

            t_start = clock()
            t_end = t_start + txack_max

            while True:
                ack = self.read_hsfz_packet(timeout=0.001)

                if ack is None:
                    if clock() > t_end:
                        raise HsfzError(None, "no packet received before timeout")
                    continue

                # Filter packet to ensure destination address corresponds to test address
                if ack[0] == Kontrollword.DIAGREQ and not ack[1][1] == testaddr:
                    continue

                if ack[0] == Kontrollword.ERROR_DIAG_APPLICATION_NOT_READY:
                    LOG.warning("received HSFZ ERROR_DIAG_APPLICATION_NOT_READY")
                    raise uds.Busy

                if ack[0] == Kontrollword.ACK and ack[1] == msg[6 : 6 + len(ack[1])]:
                    break
                LOG.warning("unexpected HSFZ packet received while waiting for ack: %r / %s", ack[0], enhex(ack[1]))

    def broadcast(self, destaddr, payload, wait_for_response, txack_max=2, testaddr=None):
        if testaddr is None:
            testaddr = self.get_default_tester_address()
        self.send_request(destaddr, payload, testaddr, txack_max)

        max_timeout = wait_for_response
        timeout = 0.25  # taken from odx-c as P2maxISO + P2_MAX_EXTENSION

        if max_timeout < timeout:
            # user wanted less timeout than given in specification, we do what the user wants
            timeout = max_timeout

        t_start = clock()
        t_end = t_start + timeout

        while True:
            try:
                sender, uds_msg = self.read_single_resp(destaddr=testaddr, timeout=0.001)
                if sender is None:
                    # received HSFZ packet was not the response we were looking for
                    continue
            except Timeout:
                if clock() > t_end:
                    break
                else:
                    continue

            try:
                sender, uds_msg = uds.DiagnoseSession.verify_response(sender, payload, uds_msg)
                if uds_msg is None:  # was response pending
                    t_end = t_start + max_timeout
                    continue
                yield (sender, uds_msg)
            except uds.UdsError as e:
                yield (e.source or sender, e)

    def send(self, destaddr, payload, testaddr=None, long_response=False, txack_max=2, wait_for_response=5.0):
        if testaddr is None:
            testaddr = self.get_default_tester_address()
        self.send_request(destaddr, payload, testaddr, txack_max)

        response_pending = bool(wait_for_response)
        max_timeout = wait_for_response

        # set the initial timeout (P6_client)
        #  DK_T3_272: 3s timeout
        #  DK_T3_276: 1.2s timeout if request AND response is < 255 byte
        timeout = 3.0 if (long_response or len(payload) >= 255) else 1.2

        if max_timeout < timeout:
            # user wanted less timeout than given in specification, we do what the user wants
            timeout = max_timeout

        uds_msg = None
        while response_pending:
            try:
                sender, uds_msg = self.read_single_resp(from_addr=destaddr, destaddr=testaddr, timeout=timeout)
                if sender is None:
                    # received HSFZ packet was not the response we were looking for
                    continue
            except Timeout:
                raise uds.NoResponse

            sender, uds_msg = uds.DiagnoseSession.verify_response(sender, payload, uds_msg)
            if uds_msg is None:
                # response pending, up the timeout to P6*_client (DK_T3_224)
                timeout = max_timeout
                continue

            response_pending = False

        return uds_msg

    def read_hsfz_packet(self, testaddr=None, timeout=bufferedsocket.TIMEOUT_DEFAULT):
        if testaddr is None:
            testaddr = self.get_default_tester_address()
        with self.connection_condition:
            while True:
                responsehdr = self.socket.recvn(6, timeout=timeout)
                if not responsehdr:
                    # no new packet in timeframe
                    return None
                if len(responsehdr) != 6:
                    raise HsfzError(None, "short packet header read: %s" % enhex(responsehdr))

                rlen, rtyp = struct.unpack("!I2s", responsehdr)

                response = self.socket.recvn(rlen, timeout=timeout)

                if len(response) != rlen:
                    raise HsfzError(
                        rtyp, "short packet read (%d < %d): %s" % (len(response), rlen, enhex(responsehdr + response))
                    )

                LOG.debug("response: %s", enhex(responsehdr + response))

                rtyp = Kontrollword[rtyp]
                if rtyp == Kontrollword.ALIVECHECK:
                    LOG.info("HSFZ Alive-Check received from %r, sending response...", response)
                    self.send_alive(testaddr=testaddr)
                    continue
                break

        return (rtyp, response)

    def send_alive(self, testaddr=None):
        if testaddr is None:
            testaddr = self.get_default_tester_address()
        hdr = struct.pack("!I2sH", 2, Kontrollword.ALIVECHECK.value(), testaddr)  # total length

        with self.connection_condition:
            while True:
                try:
                    self.socket.send(hdr)
                    break
                except EOFError:
                    self.socket = None
                    raise

    def read_single_resp(self, from_addr=None, destaddr=None, timeout=bufferedsocket.TIMEOUT_DEFAULT):
        if destaddr is None:
            destaddr = self.get_default_tester_address()
        response = self.read_hsfz_packet(testaddr=destaddr, timeout=timeout)

        if response is None:
            raise Timeout

        if response[0] != Kontrollword.DIAGREQ:
            LOG.warning("unexpected HSFZ packet received: %r / %s", response[0], enhex(response[1]))
            return None, None

        pkt_from_addr = six.indexbytes(response[1], 0)
        pkt_dest_addr = six.indexbytes(response[1], 1)

        if pkt_dest_addr != destaddr:
            LOG.warning("HSFZ diagnose packet not addressed to us: %r / %s", response[0], enhex(response[1]))
            # packet was not sent to us
            return None, None

        if from_addr is not None and pkt_from_addr != from_addr:
            LOG.warning("unexpected HSFZ diagnose packet received: %r / %s", response[0], enhex(response[1]))
            # we want a packet from a specific address and this was sent from a different address
            return None, None

        return pkt_from_addr, response[1][2:]

    def abort(self):
        if self.socket is None:
            return

        try:
            self.socket.close()
        except socket.error:
            pass
        finally:
            self.socket = None


def setup_connection(args):
    if args.host == ZGW_IDENT_AUTO:
        LOG.info("waiting for HSFZ auto-discovery...")

        server = HSFZIdentServer(("0.0.0.0", 7811), broadcast=args.broadcast)
        server.start()

        try:
            while True:
                try:
                    (host, identport), vin = server.queue.get(True, 0.05)
                    LOG.info(
                        "received VIN %r from %s:%d. Diagnosis port is %d.",
                        vin,
                        host,
                        identport,
                        HSFZ_DIAG_DEFAULT_PORT,
                    )
                    server.queue.task_done()
                    break
                except queue.Empty:
                    pass
        finally:
            server.shutdown()
    else:
        host = args.host
    return HSFZDiagnoseAdapter(host, args.port)


class HSFZIdentServer(threading.Thread, socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, bind_address, broadcast="169.254.255.255"):
        self.broadcast_address = broadcast
        self.queue = queue.Queue()
        threading.Thread.__init__(self, name="HSFZIdentServer")
        socketserver.ThreadingUDPServer.__init__(self, bind_address, None)

    def server_activate(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.sendto(struct.pack("!I2s", 0, Kontrollword.IDENT.value()), (self.broadcast_address, 6811))

    def finish_request(self, request, client_address):
        data, _ = request

        responsehdr = data[:6]
        if len(responsehdr) != 6:
            raise HsfzError(None, "short packet header read: %s" % enhex(responsehdr))
        rlen, rtyp = struct.unpack("!I2s", responsehdr)
        response = data[6:]

        if len(response) != rlen:
            raise HsfzError(
                rtyp, "short packet read (%d < %d): %s" % (len(response), rlen, enhex(responsehdr + response))
            )

        if Kontrollword[rtyp] != Kontrollword.IDENT:
            LOG.debug("ignoring HSFZ packet of type %s", Kontrollword[rtyp])
            return

        self.queue.put((client_address, response))

    def run(self):
        self.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broadcast", default="169.254.255.255", help="ZGW identification broadcast address")
    args = parser.parse_args()
    logging.basicConfig(format="%(asctime)s %(levelname)-8s %(threadName)s %(message)s")
    LOG.setLevel(logging.DEBUG)
    identserver = HSFZIdentServer(("0.0.0.0", 7811), broadcast=args.broadcast)
    identserver.start()

    LOG.info("searching for ZGW announcements...")

    try:
        while True:
            _addr, _resp = identserver.queue.get(True, 2)
            LOG.info("received VIN %s from %s:%d", _resp, _addr[0], _addr[1])
            identserver.queue.task_done()
    except queue.Empty:
        LOG.info("no further ZGW announcements received in two seconds, stopping search.")
    except KeyboardInterrupt:
        LOG.info("KeyboardInterrupt received, stopping search.")
    finally:
        identserver.shutdown()


if __name__ == "__main__":
    main()
