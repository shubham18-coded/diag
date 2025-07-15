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
import logging

import pkg_resources


class UdsError(RuntimeError):
    def __init__(self, msg, source=None):
        super(UdsError, self).__init__(msg)
        self.source = source


LOG = logging.getLogger("diagnose")

PARSER = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

CONNECTORS = []


def try_import(connector_entrypoint):
    try:
        module = connector_entrypoint.resolve()
        CONNECTORS.append(module)
    except ImportError:
        pass


for try_connector in pkg_resources.working_set.iter_entry_points("diagnose.connector"):
    try_import(try_connector)


def get_parser():
    return PARSER


def parse_args():
    CONNECTION_PARSER = PARSER.add_subparsers(help="connection type", dest="connection_type")
    CONNECTION_PARSER.required = True
    for connector in CONNECTORS:
        connector.insert_argument_parser(CONNECTION_PARSER)

    args = PARSER.parse_args()
    return args


def setup_connection(parsed_args):
    return parsed_args.setup_connection(parsed_args)
