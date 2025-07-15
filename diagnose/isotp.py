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
import struct
import threading
import time

import can

from diagnose import uds
from diagnose.tools import chunks, enhex

LOG = logging.getLogger("diagnose.isotp")

MAX_ISO_TP = 0xFFF
MAX_ISO_TP_FRAME = 7


class ISOTPError(uds.TransportProtocolError):
    def __init__(self, message):
        super(ISOTPError, self).__init__()
        self._message = message

    def __repr__(self):
        return "<ISOTPError(%s)>" % (self._message,)

    def __str__(self):
        return self.__repr__()


class Sender(threading.Thread):
    """
    messageid_out = 0x6f1
    messageid_in = 0x740
    sender = isotp.Sender(index of isotp in frame, can.Bus, messageid_out, payload,
                          prefix=b'', suffix=b'')
    sender.start()

    for msg in self.bus:
        if msg.arbitration_id & CAN_MASK != messageid_in & CAN_MASK:
            # this message is not the response ID we're looking for
            continue
        if not sender.is_alive():
            # sending finished
            break
        # this might be a flow control message from the receiving side, pass it to the isotp sender:
        sender.handle_flow(msg)
    """

    def __init__(self, index, bus, canid, payload, fill=0, prefix=b"", suffix=b"", extended_id=False):
        super(Sender, self).__init__(name="isotp-%03x" % canid)
        self.index = index
        self.bus = bus
        self.canid = canid
        self.payload = payload
        self.prefix = prefix
        self.suffix = suffix
        self.fill = fill
        self.extended_id = extended_id

        self.remaining_chunks = []

        self.can_send = False
        self.killed = False
        self.block_size = 0
        self.separation_seconds = 0

        self.send_condition = threading.Condition()
        self.data_sent = threading.Event()
        self.block_sent = threading.Event()

    def handle_flow(self, msg):
        i = self.index
        frame = msg.data
        isotp_type = (frame[i] & 0xF0) >> 4

        if isotp_type != 3:
            raise ISOTPError("expected ISO TP flow control on this channel, but got: %s" % msg)

        wait = False
        with self.send_condition:
            isotp_flag = frame[i] & 0x0F
            self.can_send = bool(isotp_flag == 0)
            self.block_size = frame[i + 1]
            separation_time = frame[i + 2]

            if 0xF1 <= separation_time <= 0xF9:
                self.separation_seconds = (separation_time & 0x0F) / 1000.0**2
            elif separation_time <= 127:
                self.separation_seconds = separation_time / 1000.0
            else:
                LOG.warning("unparsable separation time received in Flow Control Frame: %s", msg)
                self.separation_seconds = 0.05

            if self.can_send:
                # signal Clear-To-Send
                self.send_condition.notify()
                self.block_sent.clear()
                wait = True
        if wait:
            # wait for data to send so receiving will not deadlock
            self.data_sent.wait()

    def kill(self):
        self.killed = True
        # wake up sender thread
        with self.send_condition:
            self.send_condition.notify()

    def wait_for_block(self):
        while not self.block_sent.wait(timeout=max(0.001, self.separation_seconds)):
            # wait until block is sent
            # may abort on keyboard error
            pass
        # will arive here when block_sent is set
        LOG.debug("is still alive: %r", not self.killed)
        return not self.killed

    def run(self):
        try:
            maxlength = MAX_ISO_TP_FRAME - len(self.prefix) - len(self.suffix)
            LOG.debug("isotp  sending payload: %s", enhex(self.payload))
            payload_length = len(self.payload)
            if payload_length > MAX_ISO_TP:
                raise ValueError(
                    "payload too long for CAN/ISO-TP: got %d bytes, max length is %d" % (payload_length, MAX_ISO_TP)
                )
            if payload_length > maxlength:
                frame_data = struct.pack("!H", 0x1000 | payload_length) + self.payload[: maxlength - 1]
                self.remaining_chunks = chunks(self.payload[maxlength - 1 :], maxlength)
                self.block_sent.set()
            else:
                frame_data = struct.pack("!B", payload_length) + self.payload
                self.remaining_chunks = []

            LOG.debug("sending: %r", self.extended_id)
            msg = can.Message(
                arbitration_id=self.canid,
                extended_id=self.extended_id,
                data=(self.prefix + frame_data + self.suffix).ljust(self.fill, b"\0"),
            )

            LOG.debug("sending: %s", msg)
            self.bus.send(msg)
            seq = 1
            for chunk in self.remaining_chunks:
                frame_data = self.prefix + struct.pack("!B", 0x20 | seq) + chunk + self.suffix
                msg = can.Message(
                    arbitration_id=self.canid, extended_id=self.extended_id, data=frame_data.ljust(self.fill, b"\0")
                )
                seq = (seq + 1) & 0xF

                with self.send_condition:
                    # wait for Clear-To-Send
                    if not self.can_send:
                        self.data_sent.clear()
                    while not self.can_send and not self.killed:
                        self.send_condition.wait()
                    if self.killed:
                        break
                    LOG.debug("sending: %s", msg)
                    self.bus.send(msg)
                    self.data_sent.set()

                if self.block_size != 0:
                    # count down blocks
                    self.block_size -= 1
                    if self.block_size == 0:
                        # last block sent, stop for now
                        self.can_send = False
                        LOG.debug("signaling block end")
                        self.block_sent.set()

                if self.separation_seconds != 0:
                    time.sleep(self.separation_seconds)
        finally:
            self.killed = True
            LOG.debug("signaling end")
            self.block_sent.set()


class Receiver(object):
    """
    messageid_out = 0x6f1
    messageid_in = 0x740
    receiver = isotp.Receiver(index of isotp in frame, can.Bus, messageid_out, prefix=b'',
                              suffix=b'')

    tp_msg = None
    while tp_msg is None:
        msg = bus.recv(timeout=timeout)
        if msg is None:
            continue
        if msg.arbitration_id & CAN_MASK != responseid & CAN_MASK:
            continue
        if receiver.handle_received(msg):
            # received full PDU
            tp_msg = bytes(receiver.aggregated_data)
    """

    def __init__(
        self, index, bus, sendcanid, recvprefix=b"", sendprefix=b"", fill=0, buffer_size=0, extended_id=False
    ):
        self.index = index
        self.bus = bus
        self.sendcanid = sendcanid
        self.extended_id = extended_id
        self.recvprefix = recvprefix
        self.sendprefix = sendprefix
        self.fill = fill
        self.next_flow_control_after_seq = 0

        self.buffer_size = buffer_size
        if self.buffer_size >= 16:
            raise ValueError("isotp receiver buffer_size must be < 16")

        self.received_size = 0
        self.total_size = 0
        self.aggregated_data = bytearray()
        self.next_seq = 0

    def copy(self):
        return Receiver(
            self.index,
            self.bus,
            self.sendcanid,
            recvprefix=self.recvprefix,
            sendprefix=self.sendprefix,
            fill=self.fill,
            buffer_size=self.buffer_size,
            extended_id=self.extended_id,
        )

    def handle_received(self, msg):
        """
        returns True if the PDU is complete
        """
        frame = msg.data
        LOG.debug("isotp received: %s", msg)

        if not frame.startswith(self.recvprefix):
            return False

        isotp_type = (frame[self.index] & 0xF0) >> 4
        if isotp_type == 0:
            if self.total_size > 0:
                raise ISOTPError("received single frame after first frame: %s" % msg)
            size = frame[self.index] & 0x0F
            self.aggregated_data = frame[self.index + 1 : self.index + 1 + size]
            return True
        elif isotp_type == 1:
            if self.total_size > 0:
                raise ISOTPError("received first frame after first frame: %s" % msg)
            data = frame[self.index + 2 :]
            self.next_seq = 1
            self.total_size = (struct.unpack("!H", frame[self.index : self.index + 2])[0]) & 0x0FFF
            self.received_size = len(data)
            self.aggregated_data = bytearray(data)
            self.next_flow_control_after_seq += self.buffer_size
            self.next_flow_control_after_seq &= 0xF
            self.send_flow_control()
        elif isotp_type == 2:
            if self.total_size == 0:
                raise ISOTPError("received consecutive frame without a first frame: %s" % msg)
            seq = frame[self.index] & 0x0F
            data = frame[self.index + 1 :]
            if seq != self.next_seq:
                raise ISOTPError("expected sequence %02x but got %02x: %s" % (self.next_seq, seq, msg))
            self.next_seq = (self.next_seq + 1) & 0xF
            self.received_size += len(data)
            self.aggregated_data += data

            if self.received_size >= self.total_size:
                self.aggregated_data = self.aggregated_data[: self.total_size]
                LOG.debug("isotp received payload: %s", enhex(self.aggregated_data))
                return True

            if self.buffer_size > 0 and seq == self.next_flow_control_after_seq:
                LOG.debug("buffer was filled, requesting more data from ECU")
                self.next_flow_control_after_seq += self.buffer_size
                self.next_flow_control_after_seq &= 0xF
                self.send_flow_control()

        return False

    def send_flow_control(self):
        flow_data = struct.pack("BBB", 0x30, self.buffer_size, 0)
        msg = can.Message(
            arbitration_id=self.sendcanid,
            extended_id=self.extended_id,
            data=(self.sendprefix + flow_data).ljust(self.fill, b"\0"),
        )
        LOG.debug("sending: %s", msg)
        self.bus.send(msg)
