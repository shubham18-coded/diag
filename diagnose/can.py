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

import can
import six

from diagnose import uds, isotp
from diagnose.tools import enhex, clock

LOG = logging.getLogger("diagnose.can")

CAN_SFF_MASK = 0x7FF
CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_MASK = CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG

CAN_CONNECTION_TYPE = "can"


def insert_argument_parser(parser):
    can_parser = parser.add_parser(CAN_CONNECTION_TYPE, help="connect via SocketCAN")
    can_parser.set_defaults(setup_connection=setup_connection)
    can_parser.add_argument("--canif", default="can0", help="SocketCAN interface")
    can_parser.add_argument(
        "--normal", action="store_true", help="use normal addressing instead of extended addressing"
    )
    can_parser.add_argument("--interface", default="socketcan", help="use specific can interface")


BMW_UDS_ISOTP_INDEX = 1


class CANDiagnoseAdapter(uds.DiagnoseAdapter):
    # FIXME not thread safe!
    def __init__(self, extended_addressing=True, buffer_size=0):
        self.bus = None
        self.buffer_size = buffer_size
        self.extended_addressing = extended_addressing
        self.extended_ids = False

    def get_default_tester_address(self):
        return 0xF1

    def __enter__(self):
        self.bus = can.interface.Bus()  # pylint: disable=no-value-for-parameter
        return self

    def __exit__(self, exc_type, exc_valupe, traceback):
        # CAN does not need tear down
        pass

    def wait_for_connection(self):
        # can't really tell if a connection is up except by querying...
        pass

    def process_tp(
        self, destaddr, payload, sender, receiver, responseid, responsemask, long_response=False, wait_for_response=5.0
    ):
        response_pending = bool(wait_for_response)
        max_timeout = wait_for_response

        # set the initial timeout (P6_client)
        #  DK_T3_272: 3s timeout
        #  DK_T3_276: 1.2s timeout if request AND response is < 255 byte
        timeout = 3.0 if (long_response or len(payload) >= 255) else 1.2

        if timeout > max_timeout:
            # user wanted less timeout than given in specification, we do what the user wants
            timeout = max_timeout

        t_start = clock()
        t_end = t_start + timeout
        uds_msg = None

        while True:
            t_now = clock()
            if not sender.is_alive():
                break
            if t_now > t_end:
                sender.kill()
                LOG.warning("sending timed out %02x: %s", destaddr, enhex(sender.payload))
                raise uds.NoResponse
            msg = self.bus.recv(timeout=t_end - t_now)  # pylint: disable=no-member
            if msg is None:
                continue
            # filter sometimes does not work, discard messages that don't belong to us
            if msg.arbitration_id & responsemask != responseid & responsemask:
                continue
            if not sender.is_alive():
                if response_pending:
                    if receiver.handle_received(msg):
                        # received full PDU
                        uds_msg = bytes(receiver.aggregated_data)
                break
            # still in sending flow control handler
            LOG.debug("flow received: %s", msg)
            sender.handle_flow(msg)

        while response_pending:
            while uds_msg is None:
                t_now = clock()
                if t_now > t_end:
                    raise uds.NoResponse
                msg = self.bus.recv(timeout=t_end - t_now)  # pylint: disable=no-member
                if msg is None:
                    continue
                # filter sometimes does not work, discard messages that don't belong to us
                if msg.arbitration_id & responsemask != responseid & responsemask:
                    continue
                if receiver.handle_received(msg):
                    # received full PDU
                    uds_msg = bytes(receiver.aggregated_data)

            LOG.debug("response received: %s", enhex(uds_msg))

            _, uds_msg = uds.DiagnoseSession.verify_response(destaddr, payload, uds_msg)
            if uds_msg is None:
                # response pending, up the timeout to P6*_client (DK_T3_224)
                timeout = max_timeout
                # reset the received message so we'll receive again
                uds_msg = None
                continue

            response_pending = False

        return uds_msg

    def send_request(self, canid, destaddr, testaddr, payload):
        if self.extended_addressing:
            tp_index = 1
            fill = 0
            prefix = six.int2byte(destaddr)
            recvprefix = six.int2byte(testaddr)
        else:
            tp_index = 0
            fill = 8
            prefix = b""
            recvprefix = b""

        sender = isotp.Sender(
            tp_index, self.bus, canid, payload, fill=fill, prefix=prefix, extended_id=self.extended_ids
        )

        receiver = isotp.Receiver(
            tp_index,
            self.bus,
            canid,
            recvprefix=recvprefix,
            sendprefix=prefix,
            buffer_size=self.buffer_size,
            extended_id=self.extended_ids,
        )
        return sender, receiver

    def broadcast(self, destaddr, payload, wait_for_response, txack_max=None, testaddr=None):
        if testaddr is None:
            testaddr = self.get_default_tester_address()

        if self.extended_addressing:
            canid = 0x600 | testaddr
            responseid = 0x600
            responsemask = 0x700
            max_payload_length = 6
        elif self.extended_ids:
            canid = 0x18DB0000 | destaddr << 8 | testaddr
            responseid = 0x18DA0000 | testaddr << 8
            responsemask = 0x1FFFFF00
            max_payload_length = 7
        else:
            canid = testaddr
            responseid = 0x600
            responsemask = 0x600
            max_payload_length = 7

        self.bus.set_filters([{"can_id": responseid, "can_mask": responsemask}])  # pylint: disable=no-member

        if len(payload) > max_payload_length:
            raise ValueError("broadcast on can is limited to one frame per request")

        sender, receiver = self.send_request(canid, destaddr, testaddr, payload)
        # not .start(), because we don't need to start the thread when we only send one frame
        sender.run()

        max_timeout = wait_for_response
        timeout = 0.25  # taken from odx-c as P2maxISO + P2_MAX_EXTENSION

        if max_timeout < timeout:
            # user wanted less timeout than given in specification, we do what the user wants
            timeout = max_timeout

        t_start = clock()
        t_end = t_start + timeout

        receivers = {}

        while True:
            t_now = clock()
            if t_now > t_end:
                break
            msg = self.bus.recv(timeout=0.001)  # pylint: disable=no-member
            if msg is None:
                continue
            # filter sometimes does not work, discard messages that don't belong to us
            if msg.arbitration_id & responsemask != responseid & responsemask or msg.arbitration_id == canid:
                continue
            if not self.extended_addressing and not self.extended_ids:
                # in normal addressing we don't really know on which address to do flow control when
                # broadcasting.
                # since broadcasting in normal addressing is only used for scanning, we'll skip flow
                # control here.
                data = bytes(msg.data)
                LOG.debug("response received from %02x: %s", msg.arbitration_id, enhex(data))
                yield (msg.arbitration_id, data)
                continue
            sender = msg.arbitration_id & 0xFF
            if sender not in receivers:
                receivers[sender] = receiver.copy()
                if self.extended_addressing:
                    receivers[sender].sendprefix = six.int2byte(sender)
                else:
                    receivers[sender].sendcanid = 0x18DA0000 | sender << 8 | testaddr
            if receivers[sender].handle_received(msg):
                # received full PDU
                uds_msg = bytes(receivers[sender].aggregated_data)
                LOG.debug("response received from %02x: %s", sender, enhex(uds_msg))
                try:
                    sender, uds_msg = uds.DiagnoseSession.verify_response(sender, payload, uds_msg)
                    if uds_msg is None:
                        t_end = t_start + max_timeout
                        continue
                    yield (sender, uds_msg)
                except uds.UdsError as e:
                    yield (e.source or sender, e)

    def send(self, destaddr, payload, testaddr=None, long_response=False, txack_max=None, wait_for_response=5.0):
        if testaddr is None:
            testaddr = self.get_default_tester_address()

        if self.extended_addressing:
            canid = 0x600 | testaddr
            responseid = 0x600 | destaddr
            responsemask = CAN_MASK
        elif self.extended_ids:
            canid = 0x18DA0000 | destaddr << 8 | testaddr
            responseid = 0x18DA0000 | testaddr << 8 | destaddr
            responsemask = 0x1FFFFFFF
        else:
            canid = testaddr
            responseid = destaddr
            responsemask = CAN_MASK

        self.bus.set_filters([{"can_id": responseid, "can_mask": responsemask}])  # pylint: disable=no-member

        sender, receiver = self.send_request(canid, destaddr, testaddr, payload)
        sender.start()

        return self.process_tp(
            destaddr,
            payload,
            sender,
            receiver,
            responseid,
            CAN_MASK,
            long_response=long_response,
            wait_for_response=wait_for_response,
        )

    def abort(self):
        pass


def setup_connection(args):
    can.rc["channel"] = args.canif
    if args.interface == "socketcan":
        can.rc["interface"] = can.util.choose_socketcan_implementation()
    else:
        can.rc["interface"] = args.interface
    return CANDiagnoseAdapter(not args.normal, buffer_size=0)
