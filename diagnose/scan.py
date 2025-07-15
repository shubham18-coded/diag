#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import collections
import itertools
import logging
import struct
import time

import six

try:
    from progress.bar import Bar as BaseBar
except ImportError:
    # pylint: disable=no-self-use
    class BaseBar(object):
        def __init__(self, *args, **kwargs):
            pass

        def iter(self, it):
            return it

        def next(self, n=1):
            pass

        def finish(self):
            pass

    # pylint: enable=no-self-use

import diagnose
import diagnose.ecu
import diagnose.log
import diagnose.uds
from diagnose import nrc
from diagnose.tools import enhex

LOG = logging.getLogger("diagnose.scanner")
PAYLOAD_LENGTH_MAX = 4096 - 4


def auto_int_range(s):
    r = s.split("-", 1)
    if len(r) == 1:
        return [diagnose.uds.auto_int(r[0])]
    return list(range(diagnose.uds.auto_int(r[0]), diagnose.uds.auto_int(r[1]) + 1))


def test_session(ecu, setup_sessions, session_id):
    try:
        result = ecu.send(b"\x10" + six.int2byte(session_id))
    except diagnose.uds.NoResponse:
        # no response received is considered as success during session scan,
        # as they may "have the no reponse bit set"
        result = None

    # transition was successful, clean up session state after each switch
    try:
        for id_ in sorted(setup_sessions):
            ecu.send(b"\x10" + six.int2byte(id_))
    except diagnose.uds.UdsError as e:
        LOG.error(
            "failed to reset to sessions %s from session %02x: %s",
            ",".join("%02x" % id_ for id_ in sorted(setup_sessions)),
            session_id,
            e,
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )

    return result


TP_ERROR_MAX = 5


def test(sender_function, ids, results, wait, progbar=None, fuzz_length=False):
    """
    sender_function: function to send payload to device, return response payload
    ids: the ids to test
    results: result dictionary {id_:response}

    will call sender_function(sess.send, id_, payload) for id_ in ids
       where payload grows up to 4096-4 NULs whenever NRC Incorrect Message Length is returned
    will write status into results
    """
    for id_ in sorted(list(ids)):
        if progbar:
            progbar.nextid(id_)
        payload_length = 0
        tp_error_retry = 1
        while True:
            if payload_length > PAYLOAD_LENGTH_MAX:
                test_result = nrc.Incorrect_Message_Length_Or_Invalid_Format
                break
            try:
                resp = sender_function(id_, b"\0" * payload_length)
                if resp is not None:
                    test_result = "positive response: " + enhex(resp)
                else:
                    test_result = "positive response: <empty>"
                break
            except diagnose.uds.Busy as e:
                test_result = e
                break
            except diagnose.uds.NoResponse as e:
                test_result = e
                break
            except nrc.Incorrect_Message_Length_Or_Invalid_Format as e:
                if fuzz_length is True:
                    payload_length += 1
                    continue
                else:
                    test_result = e
                    break
            except diagnose.uds.UdsError as e:
                test_result = e
                break
            except diagnose.uds.TransportProtocolError as e:
                if tp_error_retry <= TP_ERROR_MAX:
                    LOG.warning("transport protocol error: %s (try %d of %d)", e, tp_error_retry, TP_ERROR_MAX)
                    tp_error_retry += 1
                    time.sleep(2)
                    continue
                else:
                    raise
            finally:
                if wait:
                    time.sleep(wait)
        ids.remove(id_)
        results[id_] = [payload_length, test_result]


Report = collections.namedtuple("Report", ("service", "security", "reading_dids", "writing_dids", "rids", "ios"))


def report_implemented(keyword, status, id_fmt, ident, payload_length=None):
    if payload_length is None:
        print_fmt = "{0!s} {1:" + id_fmt + "} appears implemented: {2!s}"
    else:
        print_fmt = "{0!s} {1:" + id_fmt + "} appears implemented: {2!s} (given {3!s} bytes)"
    LOG.info(print_fmt.format(keyword, ident, status, payload_length))


def report(args, ranges, implemented):
    # reporting
    LOG.warning("expect false-positives for ECUs that use non-standard NRC behavior")
    for id_, (_, status) in implemented["service"].items():
        if not isinstance(status, nrc.Service_Not_Supported):
            report_implemented("service", status, "02x", id_)

    for id_, (_, status) in implemented["session"].items():
        if not isinstance(status, nrc.Sub_Function_Not_Supported):
            report_implemented("Diagnostic Session", status, "02x", id_)

    for id_, (_, status) in implemented["security"].items():
        if not isinstance(status, nrc.Sub_Function_Not_Supported):
            report_implemented("Security Access", status, "02x", id_)

    if ranges["DIDR"] or ranges["DIDW"] or ranges["RID"] or ranges["IO"]:
        LOG.warning("expect false-negative for IDs that are not supported in active session!")

    for id_, (_, status) in implemented["reading_dids"].items():
        if not isinstance(status, nrc.Request_Out_Of_Range):
            report_implemented("reading DID", status, "04x", id_)

    if ranges["DIDW"] and args.allow_write:
        LOG.warning("expect false-negative for writing DIDs that do not accept the passed data!")
    for id_, (payload_length, status) in implemented["writing_dids"].items():
        if not isinstance(status, nrc.Request_Out_Of_Range) or payload_length != 1:
            report_implemented("writing DID", status, "04x", id_, payload_length=payload_length)

    for id_, (payload_length, status) in implemented["rids"].items():
        if not isinstance(status, nrc.Request_Out_Of_Range) or payload_length != 0:
            report_implemented("RID", status, "04x", id_, payload_length=payload_length)

    for id_, (_, status) in implemented["ios"].items():
        if not isinstance(status, nrc.Request_Out_Of_Range):
            report_implemented("IO", status, "04x", id_)

    for id_, responses in implemented["can-normal-addressing"].items():
        for resp_id, _ in responses:
            LOG.warning(
                "CAN / ISO-TP potential normal addressing response" " to %03x received from %03x", id_, resp_id
            )

    for id_, response in implemented["can-extended-ids"].items():
        LOG.warning("CAN / ISO-TP potential extended id response received from %02x: %s", id_, response)


class Bar(BaseBar):
    message = "Processing"
    suffix = "%(percent).1f%% - %(eta_td)s left (id: %(item)s)"

    def __init__(self, *args, **kwargs):
        super(Bar, self).__init__(*args, **kwargs)
        self.item = None
        self.index = -1

    def nextid(self, id_):
        self.item = "%04x" % id_ if id_ is not None else "----"
        self.next()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finish()


def trace_to(f, sessions):
    active_session = sessions[-1]

    def trace(
        stage=None,
        test_addr=None,
        req_data=None,
        req_addr=None,
        resp_addr=None,
        resp_data=None,
        exception=None,
        response_time=None,
        request_time=None,
    ):  # pylint: disable=unused-argument
        if stage != "response":
            return

        if exception is not None:
            # got a non-NRC exception
            description = "Error: %r" % exception
        elif resp_data is not None:
            description = enhex(resp_data, sep="")
        else:
            # only log responses
            return

        f.write(
            "%f 0x%02x 0x%03x 0x%03x %s %s\n"
            % (response_time, active_session, test_addr, req_addr, enhex(req_data, sep=""), description)
        )

    return trace


IGNORED_CAN_RANGE = (
    0x799,  # BDC-03-GATEWAY IdleMessage
    0x79A,  # BDC-03-GATEWAY IdleMessage
    0x7C0,  # BDC-03-GATEWAY FzmDebugger
    0x7C1,  # BDC-03-GATEWAY FzmDebugger
    0x7C3,  # BDC-03-GATEWAY, source unclear
    0x7C4,  # BDC-03-GATEWAY, source unclear
    0x7C5,  # BDC-03-GATEWAY, source unclear
    0x7C6,  # BDC-03-GATEWAY, source unclear
    0x7C7,  # BDC-03-GATEWAY can RX Queue maxLength Message
    0x7C8,  # BDC-03-GATEWAY can TX Queue maxLength Message
    0x7C9,  # BDC-03-GATEWAY can TX with Callback Queue Length Message
)


def main():
    parser = diagnose.get_parser()
    parser.add_argument("diagaddr", type=diagnose.uds.auto_int, help="diagnosis address of the device under test")
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="enable this if you are aware that write jobs and routines may brick" " your device",
    )
    parser.add_argument("--scan-services", action="store_true", help="scan for implemented UDS services")
    parser.add_argument("--scan-sessions", action="store_true", help="scan for implemented UDS sessions (10 xx)")
    parser.add_argument(
        "--scan-security", action="store_true", help="scan for implemented SecurityAccess levels (27 xx)"
    )
    parser.add_argument(
        "--session",
        action="append",
        type=diagnose.uds.auto_int,
        default=[],
        help="switch to sessions in this order before running scan",
    )
    parser.add_argument(
        "--did-read-range",
        action="append",
        type=auto_int_range,
        default=[],
        help="id range to scan with ReadDataByIdentifier" " (0xaaaa-0xbbbb,0xdddd-0xffff)",
    )
    parser.add_argument(
        "--did-write-range",
        action="append",
        type=auto_int_range,
        default=[],
        help="id range to scan with WriteDataByIdentifier" " (0xaaaa-0xbbbb,0xdddd-0xffff)",
    )
    parser.add_argument(
        "--io-range",
        action="append",
        type=auto_int_range,
        default=[],
        help="id range to scan with InputOutputControlByIdentifier"
        " returnControlToECU (0xaaaa-0xbbbb,0xdddd-0xffff)",
    )
    parser.add_argument(
        "--rid-range",
        action="append",
        type=auto_int_range,
        default=[],
        help="id range to scan with RoutineControl startRoutine" " (0xaaaa-0xbbbb,0xdddd-0xffff)",
    )
    parser.add_argument(
        "--range-file",
        type=argparse.FileType("r"),
        default=None,
        help="file to read scan ranges from." " each line: {DID,DIDR,DIDW,RID,IO,SID,SESS,SEC} 0xb0a0",
    )
    parser.add_argument(
        "--write-progress-file",
        default=None,
        help="file to write scan progress to, when scan is interrupted."
        " the resulting file can be used with --range-file",
    )
    parser.add_argument(
        "--wait", type=lambda s: int(s) / 1000.0, default=0, help="time in ms to wait between each request"
    )
    parser.add_argument(
        "--fuzz-payload-length",
        action="store_true",
        help="00-bytes will be appended in Write/Routine jobs while" " NRC Incorrect Message Length or Invalid Format",
    )
    parser.add_argument(
        "--trace-file",
        type=argparse.FileType("at+"),
        default=None,
        help="file to append trace to. Each line will be logged in the following"
        " format:"
        ' "float_timestamp 0xsession uds-request-hex uds-response-hex"',
    )
    parser.add_argument(
        "--testeraddress",
        type=diagnose.uds.auto_int,
        help="use this tester address instead of the default tester address",
    )
    parser.add_argument(
        "--scan-can-addressing", action="store_true", help="test for responses on non-BMW CAN addressing modes"
    )

    diagnose.log.setup_argparser(parser)
    args = diagnose.parse_args()

    diagnose.log.setup_logging(
        args, "%(asctime)s %(levelname)-8s %(message)s", clear_stdout_line=True, color_by_level=True
    )

    ranges = {
        "DIDR": set(),
        "DIDW": set(),
        "RID": set(),
        "IO": set(),
        "SID": set(),
        "SESS": set(),
        "SEC": set(),
        "CAN-NORMAL": set(),
        "CAN-EXT-ID": set(),
    }

    if args.scan_can_addressing and not args.connection_type == "can":
        LOG.error("can only test CAN addressing modes when using CAN connector.")
        return

    if args.range_file is not None:
        for line in args.range_file:
            stripped_line = line.strip()
            if stripped_line.startswith("#"):
                continue
            try:
                _type, s_id = stripped_line.split(None, 1)
                _id = diagnose.uds.auto_int(s_id)
                if _type.upper() == "DID":
                    ranges["DIDR"].add(_id)
                    ranges["DIDW"].add(_id)
                else:
                    ranges[_type.upper()].add(_id)
            except ValueError:
                LOG.error("could not parse line %r", line)
                continue

    ranges["DIDR"].update(itertools.chain(*args.did_read_range))
    ranges["DIDW"].update(itertools.chain(*args.did_write_range))
    ranges["RID"].update(itertools.chain(*args.rid_range))
    ranges["IO"].update(itertools.chain(*args.io_range))
    if args.scan_services:
        ranges["SID"].update(list(range(256)))
    if args.scan_sessions:
        ranges["SESS"].update(list(range(256)))
    if args.scan_security:
        ranges["SEC"].update(list(range(256)))
    if args.scan_can_addressing:
        ranges["CAN-NORMAL"].update(list(range(0x600, 0x800)))
        ranges["CAN-EXT-ID"].update(list(range(0x100)))

    implemented = {
        "service": {},
        "security": {},
        "reading_dids": {},
        "writing_dids": {},
        "rids": {},
        "ios": {},
        "session": {},
        "can-normal-addressing": {},
        "can-extended-ids": {},
    }
    aborted = True

    active_session = args.session or [0x01]

    with diagnose.setup_connection(args) as adapter, Bar(max=sum(len(r) for r in ranges.values())) as progbar:
        adapter.wait_for_connection()
        diagsession = diagnose.uds.DiagnoseSession(adapter, testaddr=args.testeraddress)
        if args.trace_file:
            diagsession.trace_callback = trace_to(args.trace_file, active_session)
        ecu = diagnose.ecu.ECU(diagsession, args.diagaddr)
        try:
            with ecu:
                for session in args.session:
                    LOG.info("switching to session %02x...", session)
                    ecu.send(b"\x10" + struct.pack("B", session), trace_callback=None)

                LOG.info("scanning services...")
                test(
                    lambda id_, _: ecu.send(six.int2byte(id_)),
                    ranges["SID"],
                    implemented["service"],
                    args.wait,
                    progbar=progbar,
                )

                LOG.info("scanning 0x10 DiagnosticSessionControl...")
                test(
                    lambda id_, _: test_session(ecu, active_session, id_),
                    ranges["SESS"],
                    implemented["session"],
                    args.wait,
                    progbar=progbar,
                )

                LOG.info("scanning 0x27 SecurityAccess...")
                test(
                    lambda id_, _: ecu.send(b"\x27" + six.int2byte(id_)),
                    ranges["SEC"],
                    implemented["security"],
                    args.wait,
                    progbar=progbar,
                )

                LOG.info("scanning 0x22 ReadDataByIdentifier...")
                test(
                    lambda id_, _: ecu.read_data_by_did(id_),
                    ranges["DIDR"],
                    implemented["reading_dids"],
                    args.wait,
                    progbar=progbar,
                )

                if args.allow_write:
                    LOG.info("scanning 0x2E WriteDataByIdentifier...")
                    try:
                        test(
                            lambda id_, pl: ecu.write_data_by_did(id_, b"\x00" + pl),
                            ranges["DIDW"],
                            implemented["writing_dids"],
                            args.wait,
                            progbar=progbar,
                            fuzz_length=args.fuzz_payload_length,
                        )
                    finally:
                        # payload is actually one byte bigger, since we always start with \x00
                        for v in implemented["writing_dids"].values():
                            v[0] += 1

                    LOG.info("scanning 0x31 RoutineControl...")
                    test(
                        lambda id_, pl: ecu.send(b"\x31\x01" + struct.pack("!H", id_) + pl),
                        ranges["RID"],
                        implemented["rids"],
                        args.wait,
                        progbar=progbar,
                        fuzz_length=args.fuzz_payload_length,
                    )

                    LOG.info("scanning 0x2F InputOutputControlByIdentifier...")
                    test(
                        lambda id_, _: ecu.send(b"\x2f" + struct.pack("!H", id_) + b"\0"),
                        ranges["IO"],
                        implemented["ios"],
                        args.wait,
                        progbar=progbar,
                    )
                else:
                    if ranges["DIDW"]:
                        LOG.warning("skipping 0x2E WriteDataByIdentifier scan" " due to read-only mode.")
                    if ranges["RID"]:
                        LOG.warning("skipping 0x31 RoutineControl scan" " due to read-only mode.")
                    if ranges["IO"]:
                        LOG.warning("skipping 0x2F IOControlByIdentifier scan" " due to read-only mode.")

            if ranges["CAN-NORMAL"]:
                # disable tracing
                diagsession.trace_callback = None

                # TODO: BDC-03-GATEWAY ControlIdleMessage(0): bf ff 77 00, otherwise will see cyclic
                # frames on 0x799 and 0x79a

                adapter.extended_addressing = False
                for id_ in ranges["CAN-NORMAL"]:
                    progbar.next()
                    responses = diagsession.broadcast(b"\x10\x01", 0.2, testaddr=id_)
                    for addr, response in responses:
                        if addr in IGNORED_CAN_RANGE:
                            continue
                        if id_ not in implemented["can-normal-addressing"]:
                            implemented["can-normal-addressing"][id_] = []
                        implemented["can-normal-addressing"][id_].append((addr, response))

            if ranges["CAN-EXT-ID"]:
                # disable tracing
                diagsession.trace_callback = None
                adapter.extended_ids = True

                adapter.extended_addressing = False
                for id_ in ranges["CAN-EXT-ID"]:
                    progbar.next()
                    if id_ == diagsession.testaddr:
                        # don't send diagnosis to the tester address, as the can interface will see
                        # it's own frames
                        continue
                    try:
                        response = diagsession.send(id_, b"\x10\x01", wait_for_response=0.2)
                        implemented["can-extended-ids"][id_] = response
                    except diagnose.uds.NoResponse:
                        pass
                    except diagnose.uds.UdsError as e:
                        implemented["can-extended-ids"][id_] = e

        except KeyboardInterrupt:
            LOG.info("aborting...")
            adapter.abort()
            raise
        except diagnose.uds.TransportProtocolError as e:
            LOG.error("Transport Protocol Error: %s", str(e), exc_info=LOG.isEnabledFor(logging.DEBUG))
        except diagnose.uds.UdsError as e:
            LOG.error("UDS Error: %s", str(e), exc_info=LOG.isEnabledFor(logging.DEBUG))
        else:
            aborted = False
        finally:
            if args.trace_file:
                args.trace_file.flush()
            if args.write_progress_file is not None:
                LOG.info("storing progress to %r", args.write_progress_file)
                with open(args.write_progress_file, "wt") as f:
                    for type_, ids in ranges.items():
                        for id_ in ids:
                            f.write("%s\t0x%x\n" % (type_, id_))

    report(args, ranges, implemented)
    if aborted:
        LOG.error("scan was aborted, report is incomplete.")
        if args.write_progress_file is not None:
            LOG.error("see progress file for unscanned IDs.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOG.error("CTRL-C received")
        raise
