#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods,too-many-lines

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import abc
import logging
import struct
import time

import six

import diagnose.nrc
from diagnose import UdsError
from diagnose.tools import unhex, singleton, HexInt, clock

LOG = logging.getLogger("diagnose")


def auto_int(s):
    return int(s, 0)


class NoResponse(UdsError):
    def __init__(self):
        super(NoResponse, self).__init__(None)


UDS_SID_NEGATIVE = 0x7F


class TransportProtocolError(ValueError):
    pass


class Busy(TransportProtocolError):
    pass


class DiagnoseAdapter(six.with_metaclass(abc.ABCMeta, object)):
    @abc.abstractmethod
    def send(self, destaddr, payload, testaddr=None, long_response=False, txack_max=2, wait_for_response=5.0):
        pass

    @abc.abstractmethod
    def broadcast(self, destaddr, payload, wait_for_response, txack_max=2, testaddr=None):
        pass

    @abc.abstractmethod
    def wait_for_connection(self):
        pass

    @abc.abstractmethod
    def get_default_tester_address(self):
        pass

    @abc.abstractmethod
    def __enter__(self):
        pass

    @abc.abstractmethod
    def __exit__(self, exc_type, exc_value, traceback):
        pass


@singleton
class DEFAULT(object):
    def __repr__(self):
        return "<DEFAULT>"


class DiagnoseSession(object):
    def __init__(self, connection, testaddr=None, tas=False, retry=10):
        self.tas = tas
        if testaddr is None:
            self.testaddr = connection.get_default_tester_address()
        else:
            self.testaddr = testaddr
        self.connection = connection
        self.trace_callback = None
        self.timing = {
            "MAX_BUSY_REPEAT_REQUEST": retry,  # maximum repetitions after RC21 Busy
            "REPETITION_LATENCY": 1,  # delay after RC21 Busy
            "BROADCAST_TIMEOUT": 5.05,  # how long to wait for broadcast / functional (0xdf) results
            # taken from odx-c as P2StarISO + P2_MAX_EXTENSION
            "S3": 2.1,  # Time between TesterPresentMessages, slightly higher than TXACK_MAX to avoid
            # race condition
            "P2Star": 6.5,  # maximum time for response after RC78 Response Pending
            "TXACK_MAX": 2,  # T2 TX acknowledge timeout (ms)
        }

    def send(
        self,
        destaddr,
        data,
        testaddr=None,
        force_tas=None,
        long_response=False,
        wait_for_response=DEFAULT,
        retry=DEFAULT,
        trace_callback=DEFAULT,
    ):
        r"""
        send uds data to device at destaddr, using TAS if:

        self.tas is True and force_tas is not False
        or force_tas is True

        wait_for_response accepts maximum timeout for the job to be answered
        (after Response_Pending)
        wait_for_response can be 0 if send() should not wait for a response.

        data is expected to be the encoded byte encoded string such as "\xde\xad\xbe\xef"
        """

        if testaddr is None:
            testaddr = self.testaddr
        if retry is DEFAULT:
            retry = self.timing["MAX_BUSY_REPEAT_REQUEST"]
        if trace_callback is DEFAULT:
            trace_callback = self.trace_callback

        if wait_for_response is DEFAULT:
            wait_for_response = self.timing["P2Star"]

        uds_data = data
        addr = destaddr

        if trace_callback:
            trace_callback(stage="request", test_addr=testaddr, req_addr=destaddr, req_data=data)

        using_tas = force_tas is True or (force_tas is not False and self.tas is True)
        if using_tas:
            uds_data = unhex("31 01 0f 0b") + struct.pack("!BH", addr, len(uds_data)) + uds_data
            addr = 0xF0  # change UDS destination address to TAS

        while True:
            try:
                if trace_callback:
                    request_time = clock()
                    trace_callback(
                        stage="send", test_addr=testaddr, req_addr=addr, req_data=uds_data, request_time=request_time
                    )
                response = self.connection.send(
                    addr,
                    uds_data,
                    testaddr=testaddr,
                    long_response=long_response,
                    wait_for_response=wait_for_response,
                    txack_max=self.timing["TXACK_MAX"],
                )
                if trace_callback:
                    trace_callback(
                        stage="response",
                        test_addr=testaddr,
                        req_addr=destaddr,
                        req_data=data,
                        resp_addr=destaddr,
                        resp_data=response,
                        request_time=request_time,
                        response_time=clock(),
                    )
                if using_tas:
                    # STOP_TAS
                    self.send(0xF0, unhex("31 02 0f 0b"), force_tas=False, trace_callback=None)
                return response
            except diagnose.nrc.NRC as e:
                if isinstance(e, diagnose.nrc.Busy_Repeat_Request):
                    if retry:
                        if isinstance(retry, int):
                            retry -= 1
                        LOG.info("received Busy_Repeat_Request, retrying...")
                        time.sleep(self.timing["REPETITION_LATENCY"])
                        continue
                if trace_callback:
                    trace_callback(
                        stage="response",
                        test_addr=testaddr,
                        req_addr=destaddr,
                        req_data=data,
                        resp_addr=e.source,
                        resp_data=e.response,
                        request_time=request_time,
                        response_time=clock(),
                    )
                raise
            except UdsError as e:
                if trace_callback:
                    trace_callback(
                        stage="response",
                        test_addr=testaddr,
                        req_addr=destaddr,
                        req_data=data,
                        exception=e,
                        request_time=request_time,
                        response_time=clock(),
                    )
                raise
            except (Busy, EOFError) as e:
                if retry:
                    if isinstance(retry, int):
                        retry -= 1
                    LOG.info("retrying...")
                    continue
                if trace_callback:
                    trace_callback(
                        stage="response",
                        test_addr=testaddr,
                        req_addr=destaddr,
                        req_data=data,
                        exception=e,
                        request_time=request_time,
                        response_time=clock(),
                    )
                raise

    def broadcast(
        self,
        data,
        wait_for_response=DEFAULT,
        destaddr=HexInt(0xDF),
        force_tas=None,
        testaddr=None,
        trace_callback=DEFAULT,
    ):
        if testaddr is None:
            testaddr = self.testaddr
        if trace_callback is DEFAULT:
            trace_callback = self.trace_callback
        if wait_for_response is DEFAULT:
            wait_for_response = self.timing["BROADCAST_TIMEOUT"]

        uds_data = data
        addr = destaddr

        if trace_callback:
            trace_callback(stage="request", test_addr=testaddr, req_addr=destaddr, req_data=data)

        using_tas = force_tas is True or (force_tas is not False and self.tas is True)
        if using_tas:
            uds_data = unhex("31 01 0f 0b") + struct.pack("!BH", addr, len(uds_data)) + uds_data
            addr = 0xF0  # change UDS destination address to TAS

        try:
            if trace_callback:
                request_time = clock()
                trace_callback(
                    stage="send", test_addr=testaddr, req_addr=addr, req_data=uds_data, request_time=request_time
                )

            responses = self.connection.broadcast(
                addr,
                uds_data,
                testaddr=testaddr,
                wait_for_response=wait_for_response,
                txack_max=self.timing["TXACK_MAX"],
            )

            for sender, response in responses:
                if trace_callback:
                    response_time = clock()
                    if isinstance(response, diagnose.nrc.NRC):
                        trace_callback(
                            stage="response",
                            test_addr=testaddr,
                            req_addr=destaddr,
                            req_data=data,
                            resp_addr=sender,
                            resp_data=response.response,
                            request_time=request_time,
                            response_time=response_time,
                        )
                    elif isinstance(response, UdsError):
                        trace_callback(
                            stage="response",
                            test_addr=testaddr,
                            req_addr=destaddr,
                            req_data=data,
                            exception=response,
                            request_time=request_time,
                            response_time=response_time,
                        )
                    else:
                        trace_callback(
                            stage="response",
                            test_addr=testaddr,
                            req_addr=destaddr,
                            req_data=data,
                            resp_addr=sender,
                            resp_data=response,
                            request_time=request_time,
                            response_time=response_time,
                        )
                yield sender, response
        finally:
            if using_tas:
                # STOP_TAS
                self.send(0xF0, unhex("31 02 0f 0b"), force_tas=False, trace_callback=None)

    @classmethod
    def verify_response(cls, destaddr, req_msg, uds_msg):
        """
        raise an exception for uds errors

        return (sender, uds_msg)

        sender and uds_msg is None if Response_Pending
        otherwise sender is the source of the response, and uds_msg is the response
        (TAS messages are unpacked, thus the result of this function is the inner address and
        response)
        """
        if six.indexbytes(uds_msg, 0) == UDS_SID_NEGATIVE:
            if len(uds_msg) < 2:
                raise UdsError("UDS negative response too short")
            negative_response_code = uds_msg[2:3]
            if negative_response_code == diagnose.nrc.Response_Pending.code:
                # response pending => wait for next response
                return None, None
            if negative_response_code not in diagnose.nrc.exception:
                raise diagnose.nrc.General_Reject(uds_msg, source=destaddr)
            raise diagnose.nrc.exception[negative_response_code](uds_msg, source=destaddr)

        if isinstance(req_msg, six.string_types):
            req_msg = req_msg.encode()

        if six.indexbytes(req_msg, 0) + 0x40 != six.indexbytes(uds_msg, 0):
            raise UdsError("non-negative response with wrong service id received", source=destaddr)

        if destaddr == 0xF0 and uds_msg != unhex("71 02 0f 0b"):
            inner_req_msg = req_msg[7:]
            # TAS message, unpack and parse inner message
            inner_destaddr = six.indexbytes(uds_msg, 4)
            length_b, uds_msg = uds_msg[5:7], uds_msg[7:]
            response_len = struct.unpack("!H", length_b)[0]
            if response_len != len(uds_msg):
                raise UdsError(
                    "TAS response too short: expected %d, got %r" % (response_len, uds_msg), source=destaddr
                )

            # verify encapsulated packe
            return cls.verify_response(inner_destaddr, inner_req_msg, uds_msg)
        return destaddr, uds_msg

    def read_data_by_did(self, addr, did, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("22") + struct.pack("!H", did), **kwargs)[3:]

    def write_data_by_did(self, addr, did, data, **kwargs):
        # (int, int, bytes, **Any) -> None
        self.send(addr, unhex("2E") + struct.pack("!H", did) + data, **kwargs)

    def io_control(self, addr, did, data, **kwargs):
        # (int, int, bytes, **Any) -> None
        self.send(addr, unhex("2f") + struct.pack("!H", did) + data, **kwargs)

    def start_routine(self, addr, rid, data=b"", **kwargs):
        # (int, int, bytes, **Any) -> bytes
        return self.send(addr, unhex("31 01") + struct.pack("!H", rid) + data, **kwargs)[4:]

    def stop_routine(self, addr, rid, data=b"", **kwargs):
        # (int, int, bytes, **Any) -> bytes
        return self.send(addr, unhex("31 02") + struct.pack("!H", rid) + data, **kwargs)[4:]

    def ecu_reset(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("11") + struct.pack("!B", data), **kwargs)[3:]

    def diagnostic_session_control(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("10") + struct.pack("!B", data), **kwargs)[3:]

    def clear_dtc(self, addr, data, **kwargs):
        # (int, int, bytes, **Any) -> bytes
        data_as_bytes = data if isinstance(data, bytes) else struct.pack("!I", data)[1:]
        return self.send(addr, unhex("14") + data_as_bytes, **kwargs)[2:]

    def read_dtc(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        data_as_bytes = data if isinstance(data, bytes) else struct.pack("!I", data)[1:]
        return self.send(addr, unhex("19") + data_as_bytes, **kwargs)[4:]

    def security_access(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("27") + struct.pack("!B", data), **kwargs)[3:]

    def communication_control(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("28") + struct.pack("!H", data), **kwargs)[3:]

    def request_download(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("34") + struct.pack("!B", data), **kwargs)[3:]

    def request_upload(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("35") + struct.pack("!B", data), **kwargs)[3:]

    def transfer_data(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("36") + struct.pack("!B", data), **kwargs)[3:]

    def request_transfer_exit(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("37") + struct.pack("!B", data), **kwargs)[3:]

    def control_dtc_setting(self, addr, data, **kwargs):
        # (int, int, **Any) -> bytes
        return self.send(addr, unhex("85") + struct.pack("!B", data), **kwargs)[3:]

    def read_routine(self, addr, rid, data=b"", **kwargs):
        # (int, int, bytes, **Any) -> bytes
        return self.send(addr, unhex("31 03") + struct.pack("!H", rid) + data, **kwargs)[4:]
