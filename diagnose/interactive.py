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

from IPython import embed
from IPython.utils import signatures

import diagnose
import diagnose.log
import diagnose.uds
import diagnose.ecu

LOG = logging.getLogger("diagnose.interactive")


def signature(obj):
    return str(signatures.signature(obj))


def main():
    parser = diagnose.get_parser()

    diagnose.log.setup_argparser(parser)
    args = diagnose.parse_args()

    diagnose.log.setup_logging(args, "%(asctime)s %(message)s", color_by_level=True)

    with diagnose.setup_connection(args) as adapter:
        adapter.wait_for_connection()
        diagsession = diagnose.uds.DiagnoseSession(adapter)
        send = diagsession.send  # pylint: disable=unused-variable
        broadcast = diagsession.broadcast  # pylint: disable=unused-variable
        read_data_by_did = diagsession.read_data_by_did  # pylint: disable=unused-variable
        write_data_by_did = diagsession.write_data_by_did  # pylint: disable=unused-variable

        def ecu(addr):  # pylint: disable=unused-variable
            return diagnose.ecu.ECU(diagsession, addr)

        usage = []
        for name in ("send", "broadcast", "read_data_by_did", "write_data_by_did"):
            sig = signature(locals()[name])
            usage.append("  %s%s" % (name, sig))

        usage.append("  ecu%s -> diagnose.ecu.ECU:" % signature(locals()["ecu"]))
        for name in dir(diagnose.ecu.ECU):
            if name.startswith("__"):
                continue
            sig = signature(getattr(diagnose.ecu.ECU, name))
            usage.append("    .%s%s" % (name, sig))

        embed(banner1="usage:", banner2="\n".join(usage) + "\n")


if __name__ == "__main__":
    main()
