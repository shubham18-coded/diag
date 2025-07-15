#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import logging
import math

import construct
import six

import diagnose
import diagnose.ecu
import diagnose.log
import diagnose.uds
from diagnose.tools import unhex, enhex, PrintHex, ConstructEnum, singleton

LOG = logging.getLogger("diagnose.programming")

SEC_ACCESS_PROGRAMMING = 0x11

DID_SVK_IST = 0xF101
DID_FINGERPRINT = 0xF15A
RID_CHECKMEMORY = 0x0202
RID_ADUE_PROC = 0x7000
RID_ERASEMEMORY = 0xFF00
RID_CHECKPROGRAMMINGDEPENDENCIES = 0xFF01


class ProgrammingFailed(Exception):
    pass


class TenthSecond(construct.Adapter):
    def _encode(self, obj, context):
        if obj is None:
            return 0xFFFF
        return obj * 10

    def _decode(self, obj, context):
        if obj == 0xFFFF:
            return None
        return obj / 10


DATE = collections.namedtuple("DATE", ("year", "month", "day"))


class YYMMDD(construct.Adapter):
    @staticmethod
    def bcd2int(b):
        b10 = (b & 0xF0) >> 4
        b1 = b & 0x0F
        return 10 * b10 + b1

    @staticmethod
    def int2bcd(b):
        return ((b // 10) << 4) | (b % 10)

    def _encode(self, obj, context):
        yr = self.int2bcd(obj.year % 100)
        mn = self.int2bcd(obj.month)
        dy = self.int2bcd(obj.day)
        return (yr << 16) | (mn << 8) | dy

    def _decode(self, obj, context):
        yr = self.bcd2int(six.indexbytes(obj, 0))
        mn = self.bcd2int(six.indexbytes(obj, 1))
        dy = self.bcd2int(six.indexbytes(obj, 2))
        return DATE(year=yr + 2000, month=mn, day=dy)


Fingerprint = construct.Struct(
    "programming_date" / YYMMDD(construct.Bytes(3)),
    construct.EmbeddedBitStruct(
        "is_long" / construct.Enum(construct.BitsInteger(4), long=0b1000, short=0, default=construct.Pass),
        "tester_service_id"
        / construct.Enum(
            construct.BitsInteger(4),
            independent_shop=9,
            bmw_shop=10,
            system_supplier=11,
            vehicle_plant=13,
            replacement_plant=14,
            development=15,
        ),
    ),
    "tester_id" / construct.If(construct.this.is_long == "long", construct.Int16ub),
    "programming_device_type"
    / construct.If(construct.this.is_long == "long", construct.Enum(construct.Int8ub, default=construct.Pass, l6=1)),
    "programming_device_serial_number" / construct.If(construct.this.is_long == "long", construct.Int32ub),
    "milage" / construct.If(construct.this.is_long == "long", construct.Int16ub),
)


@singleton
class SVKTypes(ConstructEnum):
    default = "RESERVED"
    subcon = construct.Bytes(1)
    value_table = {
        b"\x01": "Hardware",
        b"\x02": "HWAuspraegung",
        b"\x03": "HWFarbe",
        b"\x04": "Gatewaytable",
        b"\x05": "Codierdaten",
        b"\x06": "Bootloader",
        b"\x07": "Bootloader_slave",
        b"\x08": "Software_ECU_Speicherimage",
        b"\x09": "Flash_File_Software",
        b"\x10": "Pruefsoftware",
        b"\x11": "Programmiersystem",
        b"\x12": "Interaktive_Betriebsanleitung_Daten",
        b"\x15": "FA2FP",
        b"\x16": "FreischaltcodeFzgAuftrag",
        b"\x26": "Temporaere_Loeschroutine",
        b"\x27": "Temporaere_Programmierroutine",
        b"\xa0": "Entertainment_Daten",
        b"\xa1": "Navigation_Daten",
        b"\xa2": "Freischaltcode_Funktion",
        b"\xff": "reserved",
    }


SVKEntry = construct.Struct(
    "type" / SVKTypes, "sgbm" / PrintHex(construct.Bytes(4), sep=""), "version" / construct.Array(3, construct.Int8ub)
)

SVKTable = construct.Struct(
    "version" / construct.Const(1, subcon=construct.Int8ub),
    "programming_dependencies_checked"
    / construct.Enum(construct.Int8ub, default=construct.Pass, ok=1, not_ok=2, not_ok_hwe=3, not_ok_swe=4),
    "num_swes" / construct.Int16ub,
    "fingerprint" / Fingerprint,
    "svk" / construct.Array(construct.this.num_swes, SVKEntry),
)

ListIndexRequest = construct.Struct(
    "read_method" / construct.Default(construct.Int8ub, 0x01),
    "subroutine_id" / construct.Int16ub,
    "index" / construct.Int16ub,
)

ListRequest = construct.Struct(
    "read_method" / construct.Default(construct.Int8ub, 0x02),
    construct.EmbeddedBitStruct(
        "reserved" / construct.Const(0, subcon=construct.BitsInteger(4)),
        "memory_object_id_width" / construct.BitsInteger(4),
    ),
    "memory_object_id" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width), sep=""),
)

ListIndexResponse = construct.Struct(
    "read_method" / construct.Enum(construct.Int8ub, byid=0x02, byidx=0x01, default=construct.Pass),
    "status"
    / construct.Struct(
        "byte" / construct.Int8ub,
        "final" / construct.Computed(lambda ctx: ctx.byte in (0xFF, 0x02, 0x03)),
        "valid" / construct.Computed(lambda ctx: ctx.byte not in (0xFE, 0x01, 0x03)),
        "reserved" / construct.Computed(lambda ctx: ctx.byte not in (0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF)),
    ),
    "download_preproc_time" / TenthSecond(construct.Int16ub),
    "download_postproc_time" / TenthSecond(construct.Int16ub),
    "upload_preproc_time" / TenthSecond(construct.Int16ub),
    "upload_postproc_time" / TenthSecond(construct.Int16ub),
    construct.EmbeddedBitStruct(
        "compression_method"
        / construct.Enum(construct.BitsInteger(4), default=construct.Pass, no_compression=0, default_compression=1),
        "encryption_method" / construct.Enum(construct.BitsInteger(4), default=construct.Pass, no_encryption=0),
        "size_width" / construct.BitsInteger(4),
        "memory_object_id_width" / construct.BitsInteger(4),
    ),
    "memory_object_id" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width), sep=""),
    "memory_size" / construct.BytesInteger(construct.this.size_width),
    "application_specific" / PrintHex(construct.GreedyString(encoding=None)),
)

ProcessRequest = construct.Struct(
    "type"
    / construct.Enum(
        construct.Int8ub, default=construct.Pass, upload_pre=1, upload_post=2, download_pre=3, download_post=4
    ),
    construct.EmbeddedBitStruct(
        "reserved" / construct.Const(0, subcon=construct.BitsInteger(4)),
        "memory_object_id_width" / construct.BitsInteger(4),
    ),
    "memory_object_id" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width), sep=""),
    "application_specific" / PrintHex(construct.GreedyString(encoding=None), sep=""),
)

RequestTransfer = construct.Struct(
    "type" / construct.Enum(construct.Int8ub, download=0x34, upload=0x35),
    construct.EmbeddedBitStruct(
        "compression_method"
        / construct.Enum(construct.BitsInteger(4), default=construct.Pass, no_compression=0, default_compression=1),
        "encryption_method" / construct.Enum(construct.BitsInteger(4), default=construct.Pass, no_encryption=0),
        "size_width" / construct.BitsInteger(4),
        "memory_object_id_width" / construct.BitsInteger(4),
    ),
    "memory_object_id" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width), sep=""),
    "memory_size" / construct.BytesInteger(construct.this.size_width),
)

TransferResponse = construct.Struct(
    construct.EmbeddedBitStruct(
        "num_bytes_per_block_width" / construct.BitsInteger(4),
        "reserved" / construct.Const(0, subcon=construct.BitsInteger(4)),
    ),
    "num_bytes_per_block" / construct.BytesInteger(construct.this.num_bytes_per_block_width),
)

TransferData = construct.Struct(
    "type" / construct.Const(0x36, subcon=construct.Int8ub),
    "block" / construct.Int8ub,
    "data" / construct.Default(construct.GreedyString(encoding=None), b""),
)

EraseMemoryIndicated = construct.Struct(
    "method" / construct.Default(construct.Int8ub, 0x02),
    construct.EmbeddedBitStruct(
        "memory_object_id_width" / construct.BitsInteger(4),
        "reserved" / construct.Const(0, subcon=construct.BitsInteger(4)),
    ),
    "swe_desc_ptr" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width)),
    "activation_code" / construct.Default(construct.Int8ub, 0x06),
)

CheckMemoryIndicated = construct.Struct(
    "method" / construct.Default(construct.Int8ub, 0x12),
    construct.EmbeddedBitStruct(
        "memory_object_id_width" / construct.BitsInteger(4),
        "reserved" / construct.Const(0, subcon=construct.BitsInteger(4)),
    ),
    "swe_desc_ptr" / PrintHex(construct.BytesInteger(construct.this.memory_object_id_width)),
    "reserved" / construct.Default(construct.Int16ub, 0),
)

REUSE = object()


class ProgrammingECU(diagnose.ecu.ECU):
    def __init__(self, diag, addr):
        super(ProgrammingECU, self).__init__(diag, addr)
        self.svk_ist = None
        self.btldid = None

    @classmethod
    def cast(cls, ecu):
        return cls(ecu.diag, ecu.addr)

    def reload_svk(self):
        self.svk_ist = SVKTable.parse(self.read_data_by_did(DID_SVK_IST))
        self.btldid = [svk.sgbm for svk in self.svk_ist.svk if svk.type == SVKTypes.Bootloader][0]

    def get_svk(self):
        if self.svk_ist is None:
            self.reload_svk()
        return self.svk_ist

    @property
    def svk_swe(self):
        if self.svk_ist is None:
            self.reload_svk()
        return self.svk_ist.svk

    @property
    def svk_fingerprint(self):
        if self.svk_ist is None:
            self.reload_svk()
        return self.svk_ist.fingerprint

    @property
    def svk_btldid(self):
        if self.svk_ist is None:
            self.reload_svk()
        return self.btldid

    def prepare_flash(
        self,
        l3key,
        l3hash,
        ptr_width_bits=32,
        skip_erase=False,
        swe_desc_ptr=None,
        fingerprint=REUSE,
        testerid=b"\0\0\0\0",
    ):
        """
        unlock programming session, prepare for transfer.
        **Requires diagnose_pentesting for implementation of the authentication.**

        fingerprint can be: bytes to use as fingerprint, REUSE if the previous fingerprint should be
        written again or a falsish value if no fingerprint should be written
        testerid defaults to 00000000
        """
        import diagnose_pentesting

        if fingerprint is REUSE:
            LOG.debug("reusing fingerprint: %s", repr(self.svk_fingerprint))
            fingerprint = Fingerprint.build(self.svk_fingerprint)
        LOG.debug("encoded fingerprint: %s", enhex(fingerprint))

        # unlock session
        diagnose_pentesting.keys.auth(self, SEC_ACCESS_PROGRAMMING, l3key, l3hash, testerid=testerid)

        if fingerprint:
            # Write Fingerprint
            self.write_data_by_did(DID_FINGERPRINT, fingerprint)

        if not skip_erase:
            if swe_desc_ptr is None:
                raise ValueError("need swe_desc_ptr if performing memory erase")
            # Erase Memory
            ptr_width = ptr_width_bits // 8
            erase_request = EraseMemoryIndicated.build(
                {"memory_object_id_width": ptr_width, "swe_desc_ptr": swe_desc_ptr}
            )
            resp = self.start_routine(RID_ERASEMEMORY, erase_request)
            if six.indexbytes(resp, 0) != 0:
                LOG.error("erase memory failed: %s", enhex(resp))
                raise ProgrammingFailed

    def flash(
        self, flash_addr, flash_data, flash_size=None, ptr_width_bits=32, size_ptr_width_bits=None, compressed=False
    ):
        if flash_size is None:
            flash_size = len(flash_data)
        # Request Download
        transfer = {
            "type": "download",
            "encryption_method": "no_encryption",
            "size_width": (size_ptr_width_bits or ptr_width_bits) // 8,
            "memory_object_id_width": ptr_width_bits // 8,
            "compression_method": "default_compression" if compressed else "no_compression",
            "memory_object_id": flash_addr,
            "memory_size": flash_size,
        }

        transfer_request = RequestTransfer.build(transfer)
        download_response = self.send(transfer_request)[1:]
        block_info = TransferResponse.parse(download_response)

        # block size returned by the Request Download includes SID and Block Ctr (FP5_6591), so -2
        block_size = block_info.num_bytes_per_block - 2

        num_transfers = int(math.ceil(float(len(flash_data)) / block_size))
        LOG.info("num transfers: %d", num_transfers)
        for i in range(num_transfers):
            block_data = flash_data[i * block_size : (i + 1) * block_size]
            block = (i + 1) % 0xFF
            self.send(TransferData.build({"block": block, "data": block_data}))
        self.send(b"\x37")

    def check_memory(self, swe_desc_ptr, ptr_width_bits=32):
        ptr_width = ptr_width_bits // 8
        check_request = CheckMemoryIndicated.build({"memory_object_id_width": ptr_width, "swe_desc_ptr": swe_desc_ptr})
        resp = self.start_routine(RID_CHECKMEMORY, check_request)
        if six.indexbytes(resp, 0) != 0:
            LOG.error("check memory failed: %s", enhex(resp))
            raise ProgrammingFailed

    def check_programming_dependencies(self):
        resp = self.start_routine(RID_CHECKPROGRAMMINGDEPENDENCIES, b"")
        if six.indexbytes(resp, 0) != 1:
            LOG.error("check programming dependencies failed: %s", enhex(resp))
            raise ProgrammingFailed

    def adue_list_objects(
        self, id_prefix_routine, id_prefix_subroutine, start_index=0, end_index=0x10000, stop_at_final=True
    ):
        for i in range(start_index, end_index):
            try:
                list_entry = self.adue_get_object_by_index(id_prefix_routine, id_prefix_subroutine, i)
            except diagnose.nrc.Request_Out_Of_Range:
                LOG.warning("got Request_Out_Of_Range but no final list entry")
                break
            if not list_entry.status.valid:
                if stop_at_final:
                    LOG.warning("got invalid list entry at index %04x, but no final before", i)
                continue
            yield list_entry
            if stop_at_final and list_entry.status.final:
                break

    def adue_get_object_by_index(self, id_prefix_routine, id_prefix_subroutine, index):
        req = ListIndexRequest.build({"subroutine_id": id_prefix_subroutine, "index": index})
        msg = self.start_routine(id_prefix_routine, req)
        LOG.info("%04x%04x[%d]: %s", id_prefix_routine, id_prefix_subroutine, index, enhex(msg))
        list_entry = ListIndexResponse.parse(msg)
        LOG.info("%04x%04x[%d]: %s", id_prefix_routine, id_prefix_subroutine, index, repr(list_entry))
        if list_entry.status.reserved:
            LOG.warning("reserved status of list object: 0x%02x", list_entry.status.byte)
        return list_entry

    def adue_get_object(self, memory_object_id, memory_object_id_width):
        req = ListRequest.build(
            {"memory_object_id_width": memory_object_id_width, "memory_object_id": memory_object_id}
        )
        shift_bytes = memory_object_id_width - 2
        rid = (memory_object_id >> 8 * shift_bytes) & 0xFFFF
        msg = self.start_routine(rid, req)
        LOG.info("0x%0*x: %s", memory_object_id_width, memory_object_id, enhex(msg))
        list_entry = ListIndexResponse.parse(msg)
        LOG.info("0x%0*x: %s", memory_object_id_width, memory_object_id, repr(list_entry))
        if list_entry.status.reserved:
            LOG.warning("reserved status of list object: 0x%02x", list_entry.status.byte)
        return list_entry

    def adue_read(self, obj, ignore_invalid=False):
        if not obj.status.valid:
            if ignore_invalid:
                LOG.warning("reading invalid list entry")
            else:
                raise ValueError("cannot read invalid list entry got invalid list entry")

        memory_size = obj.memory_size

        if obj.upload_preproc_time is not None:
            preproc_req = ProcessRequest.build(dict(obj, type="upload_pre"))
            preproc_resp = self.start_routine(RID_ADUE_PROC, preproc_req)

            if preproc_resp != b"\x01":
                LOG.error("preprocessing returned NOT-OK: %s", enhex(preproc_resp))

            if memory_size == 0 or memory_size == 256**obj.memory_size - 1:
                list_req = ListRequest.build(
                    {"memory_object_id_width": obj.memory_object_id_width, "memory_object_id": obj.memory_object_id}
                )
                shift_bytes = obj.memory_object_id_width - 2
                rid = (obj.memory_object_id >> 8 * shift_bytes) & 0xFFFF
                msg = self.start_routine(rid, list_req)
                obj = ListIndexResponse.parse(msg)
                if obj.status.reserved:
                    LOG.warning("reserved status of list object: 0x%02x", obj.status.byte)
                if not obj.status.valid:
                    if ignore_invalid:
                        LOG.warning("got invalid list entry after preprocessing")
                    else:
                        raise ValueError("got invalid list entry after preprocessing")
                memory_size = obj.memory_size

        if memory_size == 0:
            LOG.info("no data to read!")
            return b""

        self.send(unhex("10 03"))
        transfer_request = RequestTransfer.build(dict(obj, type="upload"))
        upload_response = self.send(transfer_request)[1:]
        block_info = TransferResponse.parse(upload_response)

        # block size returned by the Request Download includes SID and Block Ctr (FP5_6591), so -2
        block_size = block_info.num_bytes_per_block - 2

        num_transfers = int(math.ceil(float(memory_size) / block_size))
        data = bytearray()
        for block in range(1, num_transfers + 1):
            data += self.send(TransferData.build({"block": block % 0xFF}), long_response=True)[2:]
        self.send(b"\x37")

        if obj.upload_postproc_time is not None:
            postproc_req = ProcessRequest.build(dict(obj, type="upload_post"))
            postproc_resp = self.start_routine(RID_ADUE_PROC, postproc_req)

            if postproc_resp != b"\x01":
                LOG.error("postprocessing returned NOT-OK: %s", enhex(postproc_resp))

        return bytes(data)

    def adue_write(self, obj, data):
        memory_size = len(data)

        if obj.download_preproc_time is not None:
            preproc_req = ProcessRequest.build(dict(obj, type="download_pre"))
            preproc_resp = self.start_routine(RID_ADUE_PROC, preproc_req)

            if preproc_resp != b"\x01":
                LOG.error("preprocessing returned NOT-OK: %s", enhex(preproc_resp))

        self.send(unhex("10 03"))

        td = dict(obj, type="download", memory_size=memory_size)
        transfer_request = RequestTransfer.build(td)
        download_response = self.send(transfer_request)[1:]

        block_info = TransferResponse.parse(download_response)

        # block size returned by the Request Download includes SID and Block Ctr (FP5_6591), so -2
        block_size = block_info.num_bytes_per_block - 2

        num_transfers = int(math.ceil(float(memory_size) / block_size))
        for i in range(num_transfers):
            block_data = data[i * block_size : (i + 1) * block_size]
            block = (i + 1) % 0xFF
            self.send(TransferData.build({"block": block, "data": block_data}))
        self.send(b"\x37")

        if obj.download_postproc_time is not None:
            postproc_req = ProcessRequest.build(dict(obj, type="download_post"))
            postproc_resp = self.start_routine(RID_ADUE_PROC, postproc_req)

            if postproc_resp != b"\x01":
                LOG.error("postprocessing returned NOT-OK: %s", enhex(postproc_resp))


def get_svk(ecu):
    return ProgrammingECU.cast(ecu).get_svk()


def main(args):
    with diagnose.setup_connection(args) as adapter:
        try:
            adapter.wait_for_connection()
            diagsession = diagnose.uds.DiagnoseSession(adapter)
            ecu = ProgrammingECU(diagsession, 0x63)

            objs = list(ecu.adue_list_objects(0x1002, 0))
            for obj in objs:
                print(obj)

            idr = ecu.adue_read(objs[0])
            print(repr(idr))
            # ecu.adue_write(objs[0], idr)

        except KeyboardInterrupt:
            pass
        except BaseException as e:
            LOG.exception("bad %s", e)


if __name__ == "__main__":
    parser = diagnose.get_parser()
    diagnose.log.setup_argparser(parser)
    _args = diagnose.parse_args()

    diagnose.log.setup_logging(
        _args, "%(asctime)s %(levelname)-8s %(message)s", clear_stdout_line=True, color_by_level=True
    )
    main(_args)
