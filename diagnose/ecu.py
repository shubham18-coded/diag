#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods,too-many-lines

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import threading
from collections import defaultdict

import diagnose.nrc
from diagnose.tools import unhex

LOG = logging.getLogger("diagnose.ecu")
READ = 0
WRITE = 1
IO = 2
ROUTINE_START = 3
ROUTINE_STOP = 4
ECU_RESET = 5
DIAGNOSTIC_SESSION_CONTROL = 6
CLEAR_DTC = 7
READ_DTC = 8
SECURITY_ACCESS = 9
COMMUNICATION_CONTROL = 10
REQUEST_DOWNLOAD = 11
REQUEST_UPLOAD = 12
TRANSFER_DATA = 13
REQUEST_TRANSFER_EXIT = 14
CONTROL_DTC_SETTING = 15
READ_ROUTINE = 16

UNSUPPORTED = (
    diagnose.nrc.Service_Not_Supported,
    diagnose.nrc.Sub_Function_Not_Supported,
    diagnose.nrc.Request_Out_Of_Range,
)


class PresentThread(threading.Thread):
    def __init__(self, ecu, rid, wait_for_response, interval=2):
        super(PresentThread, self).__init__(name="PresentThread-0x%02x" % ecu.addr)
        self.ecu = ecu
        self.rid = rid
        self._running = True
        self.timeout = threading.Event()
        self.interval = interval
        self.wait_for_response = wait_for_response

    def run(self):
        while self._running:
            LOG.debug("%s waiting", self.getName())
            self.timeout.wait(self.interval)
            if self._running and not self.timeout.is_set():
                LOG.info("%s sending keep-alive...", self.getName())
                self.ecu.send(unhex("3e {}".format(self.rid)), wait_for_response=self.wait_for_response)
            self.timeout.clear()

    def stop(self):
        LOG.debug("%s stopped", self.getName())
        self._running = False
        self.timeout.set()

    def active(self):
        self.timeout.set()


class ECU(object):
    def __init__(self, diag, addr, tester_present_interval=None):
        self.diag = diag
        self.addr = addr
        self.failing_ids = defaultdict(dict)
        self.present_thread = None
        self.tester_present_interval = tester_present_interval
        if self.tester_present_interval:
            self.tester_present_interval = self.diag.timing["S3"]

    def __enter__(self):
        self.start_tester_present()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_tester_present()

    def start_tester_present(self, rid="80"):
        if rid == "80":
            wait_for_response = 0
        else:
            wait_for_response = 0.5
            rid = "00"
        self.present_thread = PresentThread(
            self, rid=rid, wait_for_response=wait_for_response, interval=self.tester_present_interval
        )
        self.present_thread.start()

    def stop_tester_present(self):
        self.present_thread.stop()
        self.present_thread = None

    def active(self):
        if self.present_thread is not None:
            self.present_thread.active()

    def log_id(self, operation, did, exception):
        self.failing_ids[operation][did] = exception

    def check_id_supported(self, operation, did):
        if did not in self.failing_ids[operation]:
            return None

        # no exception stored, did not fail ==> id works
        return not self.failing_ids[operation][did] is False

    def send(self, data, **kwargs):
        # (bytes, **Any) -> bytes
        self.active()
        return self.diag.send(self.addr, data, **kwargs)

    def read_data_by_did(self, did, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.read_data_by_did(self.addr, did, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(READ, did, e)
            raise
        else:
            self.log_id(READ, did, False)

    def write_data_by_did(self, did, data, **kwargs):
        # (int, bytes, **Any) -> None
        self.active()
        try:
            self.diag.write_data_by_did(self.addr, did, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(WRITE, did, e)
            raise
        else:
            self.log_id(WRITE, did, False)

    def io_control(self, did, data, **kwargs):
        # (int, bytes, **Any) -> None
        self.active()
        try:
            self.diag.io_control(self.addr, did, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(IO, did, e)
            raise
        else:
            self.log_id(IO, did, False)

    def start_routine(self, rid, data=b"", **kwargs):
        # (int, bytes, **Any) -> bytes
        self.active()
        try:
            return self.diag.start_routine(self.addr, rid, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(ROUTINE_START, rid, e)
            raise
        else:
            self.log_id(ROUTINE_START, rid, False)

    def stop_routine(self, rid, data=b"", **kwargs):
        # (int, bytes, **Any) -> bytes
        self.active()
        try:
            return self.diag.stop_routine(self.addr, rid, data=data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(ROUTINE_STOP, rid, e)
            raise
        else:
            self.log_id(ROUTINE_STOP, rid, False)

    def read_routine(self, rid, data=b"", **kwargs):
        # (int, bytes, **Any) -> bytes
        self.active()
        try:
            return self.diag.read_routine(self.addr, rid, data=data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(READ_ROUTINE, rid, e)
            raise
        else:
            self.log_id(READ_ROUTINE, rid, False)

    def ecu_reset(self, data, **kwargs):
        # (int, **Any) -> bytes
        try:
            return self.diag.ecu_reset(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(ECU_RESET, data, e)
            raise
        else:
            self.log_id(ECU_RESET, data, False)

    def diagnostic_session_control(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.diagnostic_session_control(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(DIAGNOSTIC_SESSION_CONTROL, data, e)
            raise
        else:
            self.log_id(DIAGNOSTIC_SESSION_CONTROL, data, False)

    def clear_dtc(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.clear_dtc(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(CLEAR_DTC, data, e)
            raise
        else:
            self.log_id(CLEAR_DTC, data, False)

    def read_dtc(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.read_dtc(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(READ_DTC, data, e)
            raise
        else:
            self.log_id(READ_DTC, data, False)

    def security_access(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.security_access(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(SECURITY_ACCESS, data, e)
            raise
        else:
            self.log_id(SECURITY_ACCESS, data, False)

    def communication_control(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.communication_control(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(COMMUNICATION_CONTROL, data, e)
            raise
        else:
            self.log_id(COMMUNICATION_CONTROL, data, False)

    def request_download(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.request_download(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(REQUEST_DOWNLOAD, data, e)
            raise
        else:
            self.log_id(REQUEST_DOWNLOAD, data, False)

    def request_upload(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.request_upload(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(REQUEST_UPLOAD, data, e)
            raise
        else:
            self.log_id(REQUEST_UPLOAD, data, False)

    def transfer_data(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.transfer_data(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(TRANSFER_DATA, data, e)
            raise
        else:
            self.log_id(TRANSFER_DATA, data, False)

    def request_transfer_exit(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.request_transfer_exit(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(REQUEST_TRANSFER_EXIT, data, e)
            raise
        else:
            self.log_id(REQUEST_TRANSFER_EXIT, data, False)

    def control_dtc_setting(self, data, **kwargs):
        # (int, **Any) -> bytes
        self.active()
        try:
            return self.diag.control_dtc_setting(self.addr, data, **kwargs)
        except UNSUPPORTED as e:
            self.log_id(CONTROL_DTC_SETTING, data, e)
            raise
        else:
            self.log_id(CONTROL_DTC_SETTING, data, False)
