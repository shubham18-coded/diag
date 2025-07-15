# Copyright (C) 2019. BMW CTW PT. All rights reserved.

import diagnose
import logging
import math

from diagnose.tools import unhex, enhex

from diagnose.programming import (
    ListIndexRequest,
    ListIndexResponse,
    ListRequest,
    ProcessRequest,
    RID_ADUE_PROC,
    RequestTransfer,
    TransferResponse,
    TransferData,
)

LOG = logging.getLogger("diagnose.adue")


class Adue(object):
    """Implements Adue"""

    def __init__(self, ecu):
        """Adue Initializer

        :param ecu ecu: Ecu
        """
        self.ecu = ecu
        self.memory_size = None
        self.block_size = None

    def list_objects(
        self, id_prefix_routine, id_prefix_subroutine, start_index=0, end_index=0x10000, stop_at_final=True
    ):
        """Adue List Objects

        :param int id_prefix_routine: id prefix routine.
        :param int id_prefix_subroutine: id prefix subroutine.
        :param int start_index: start index.
        :param int end_index: end index.
        :param boolean stop_at_final: stop at final.
        """
        for i in range(start_index, end_index):
            try:
                list_entry = self.get_object_by_index(id_prefix_routine, id_prefix_subroutine, i)
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

    def get_object_by_index(self, id_prefix_routine, id_prefix_subroutine, index):
        """Adue Get Object by Index

        :param int id_prefix_routine: id prefix routine.
        :param int id_prefix_subroutine: id prefix subroutine.
        :param int index: object index.
        :return type: List entry
        """
        req = ListIndexRequest.build({"subroutine_id": id_prefix_subroutine, "index": index})
        msg = self.ecu.start_routine(id_prefix_routine, req)
        LOG.info("%04x%04x[%d]: %s", id_prefix_routine, id_prefix_subroutine, index, enhex(msg))
        list_entry = ListIndexResponse.parse(msg)
        LOG.info("%04x%04x[%d]: %s", id_prefix_routine, id_prefix_subroutine, index, repr(list_entry))
        if list_entry.status.reserved:
            LOG.warning("reserved status of list object: 0x%02x", list_entry.status.byte)
        return list_entry

    def get_object(self, memory_object_id, memory_object_id_width):
        """Adue Get Object

        :param int memory_object_id: memory object identifier.
        :param int memory_object_id_width: memory object identifier width.
        :return type: List entry
        """
        req = ListRequest.build(
            {"memory_object_id_width": memory_object_id_width, "memory_object_id": memory_object_id}
        )

        shift_bytes = memory_object_id_width - 2
        rid = (memory_object_id >> 8 * shift_bytes) & 0xFFFF
        msg = self.ecu.start_routine(rid, req)
        LOG.info("0x%0*x: %s", memory_object_id_width, memory_object_id, enhex(msg))
        list_entry = ListIndexResponse.parse(msg)
        LOG.info("0x%0*x: %s", memory_object_id_width, memory_object_id, repr(list_entry))
        if list_entry.status.reserved:
            LOG.warning("reserved status of list object: 0x%02x", list_entry.status.byte)
        return list_entry

    def read(self, obj, ignore_invalid=False):
        """Adue Read

        :param int obj: object.
        :param bool ignore_invalid: if invalid list is to be ignored.
        :return bytes: data read.

        :raises ValueError: If object is invalid or got invalid list entry after
            preprocessing
        """
        if not obj.status.valid:
            if ignore_invalid:
                LOG.warning("reading invalid list entry")
            else:
                raise ValueError("cannot read invalid list entry got invalid list entry")

        self.memory_size = obj.memory_size
        self._pre_processing(obj, type="upload_pre", ignore_invalid=ignore_invalid)

        if self.memory_size == 0:
            LOG.info("no data to read!")
            return b""

        self.ecu.send(unhex("10 03"))
        self._transfer_request(obj, type="upload")
        uploaded_data = self._transfer_data(type="upload")
        self._post_processing(obj, type="upload_post")

        return bytes(uploaded_data)

    def write(self, obj, data):
        """Adue Write

        :param int obj: object.
        :param int data: data to write.
        """
        self.memory_size = len(data)
        self._pre_processing(obj, type="download_pre")
        self.ecu.send(unhex("10 03"))

        self._transfer_request(obj, type="download")
        self._transfer_data(data=data, type="download")

        self._post_processing(obj, type="download_post")

    def _pre_processing(self, obj, type=type, ignore_invalid=False):
        """Adue Write

        :param int obj: object.
        :param str type: operation type.
        :param bool ignore_invalid: if invalid list is to be ignored.

        :raises ValueError: If got invalid list entry after preprocessing.
        """

        preproc_time = obj.upload_preproc_time if type == "upload_pre" else obj.download_preproc_time

        if preproc_time is not None:
            preproc_req = ProcessRequest.build(dict(obj, type=type))
            preproc_resp = self.ecu.start_routine(RID_ADUE_PROC, preproc_req)

            if preproc_resp != b"\x01":
                LOG.error("preprocessing returned NOT-OK: %s", enhex(preproc_resp))

            if type == "upload_pre":
                list_req = ListRequest.build(
                    {
                        "memory_object_id_width": obj.memory_object_id_width,
                        "memory_object_id": obj.memory_object_id,
                    }
                )
                shift_bytes = obj.memory_object_id_width - 2
                rid = (obj.memory_object_id >> 8 * shift_bytes) & 0xFFFF
                msg = self.ecu.start_routine(rid, list_req)
                obj = ListIndexResponse.parse(msg)
                if obj.status.reserved:
                    LOG.warning("reserved status of list object: 0x%02x", obj.status.byte)
                if not obj.status.valid:
                    if ignore_invalid:
                        LOG.warning("got invalid list entry after preprocessing")
                    else:
                        raise ValueError("got invalid list entry after preprocessing")
                self.memory_size = obj.memory_size

    def _transfer_request(self, obj, type=type):
        """Adue Write

        :param int obj: object.
        :param str type: operation type
        """
        td = dict(obj, type=type, memory_size=self.memory_size)

        transfer_request = RequestTransfer.build(td)
        response = self.ecu.send(transfer_request)[1:]
        block_info = TransferResponse.parse(response)

        # block size returned by the Request Download includes SID and Block Ctr (FP5_6591), so -2
        self.block_size = block_info.num_bytes_per_block - 2

    def _transfer_data(self, data=None, type=type):
        """Adue Write

        :param int data: data to be transfered.
        :param str type: operation type.
        :return type: bytearray|None
        """
        uploaded_data = None
        num_transfers = int(math.ceil(float(self.memory_size) / self.block_size))
        if type == "download":
            for i in range(num_transfers):
                block_data = data[i * self.block_size : (i + 1) * self.block_size]
                block = (i + 1) % 0xFF
                self.ecu.send(TransferData.build({"block": block, "data": block_data}))
        else:
            uploaded_data = bytearray()
            for block in range(1, num_transfers + 1):
                uploaded_data += self.ecu.send(TransferData.build({"block": block % 0xFF}), long_response=True)[2:]

        self.ecu.send(b"\x37")

        return uploaded_data

    def _post_processing(self, obj, type=type):
        """Adue Write

        :param int obj: object.
        :param str type: operation type
        """
        postproc_time = obj.upload_postproc_time if type == "upload_post" else obj.download_postproc_time
        if postproc_time is not None:
            postproc_req = ProcessRequest.build(dict(obj, type=type))
            postproc_resp = self.ecu.start_routine(RID_ADUE_PROC, postproc_req)

            if postproc_resp != b"\x01":
                LOG.error("postprocessing returned NOT-OK: %s", enhex(postproc_resp))
