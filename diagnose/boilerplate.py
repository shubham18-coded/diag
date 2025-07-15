#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import diagnose
import diagnose.log
import diagnose.uds
import diagnose.ecu


def main():
    parser = diagnose.get_parser()
    diagnose.log.setup_argparser(parser)
    args = diagnose.parse_args()

    diagnose.log.setup_logging(args, "%(asctime)s %(levelname)-8s %(message)s", color_by_level=True)

    with diagnose.setup_connection(args) as adapter:
        adapter.wait_for_connection()
        diagsession = diagnose.uds.DiagnoseSession(adapter)

        # your code here! example code follows
        # ATM1
        ecu = diagnose.ecu.ECU(diagsession, 0x61)
        # Get VIN
        resp = ecu.read_data_by_did(0xF190)
        print(repr(resp))


if __name__ == "__main__":
    main()
