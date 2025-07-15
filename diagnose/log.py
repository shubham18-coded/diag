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
import sys

import six


class Color(object):
    def __init__(self, escape=None):
        if escape and not isinstance(escape, (six.text_type, tuple)):
            raise TypeError("Color parts must be unicode string or tuple")
        self.escape = escape

    def format(self, use_color=True):
        if isinstance(self.escape, tuple):
            return "".join(
                part.format(use_color=use_color) if isinstance(part, Color) else part for part in self.escape
            )
        return self.escape if use_color else ""

    def __repr__(self):
        return "<Color(%r)>" % (self.escape,)

    def __hash__(self):
        return hash(self.escape)

    def __eq__(self, other):
        if not isinstance(other, Color):
            return NotImplemented
        return self.escape == other.escape

    def __ne__(self, other):
        if not isinstance(other, Color):
            return NotImplemented
        return self.escape != other.escape

    def __add__(self, other):
        if isinstance(self.escape, six.text_type):
            left = (self,)
        else:
            left = self.escape
        if isinstance(other, Color):
            if isinstance(other.escape, six.text_type):
                right = (other,)
            else:
                right = other.escape
            return Color(left + right)
        elif isinstance(other, six.text_type):
            return Color(left + (other,))
        return NotImplemented

    def __radd__(self, other):
        if isinstance(other, six.text_type):
            if isinstance(self.escape, six.text_type):
                right = (self,)
            else:
                right = self.escape
            return Color((other,) + right)
        return NotImplemented


RESET = Color("\x1b[m")
NORMAL = Color("\x1b[22m")
BOLD = Color("\x1b[1m")

BLACK = Color("\x1b[30m")
RED = Color("\x1b[31m")
GREEN = Color("\x1b[32m")
YELLOW = Color("\x1b[33m")
BLUE = Color("\x1b[34m")
MAGENTA = Color("\x1b[35m")
CYAN = Color("\x1b[36m")
WHITE = Color("\x1b[37m")

LEVEL_COLORS = {
    "CRITICAL": RED + BOLD,
    "ERROR": RED,
    "WARNING": YELLOW,
    "INFO": CYAN,
    "DEBUG": BLUE,
}


class ColorFormatter(logging.Formatter):
    def __init__(self, force_color=False, color_by_level=False, **kwargs):
        super(ColorFormatter, self).__init__(**kwargs)
        self.force_color = force_color
        self.color_by_level = color_by_level

    def formatColor(self, record, use_color=False):
        use_color |= self.force_color
        new_record = logging.makeLogRecord(record.__dict__)
        new_record.args = tuple(a.format(use_color) if isinstance(a, Color) else a for a in record.args)
        if self.color_by_level:
            levelcolor = LEVEL_COLORS.get(new_record.levelname, RESET).format(use_color)
            new_record.msg = "%s%s" % (levelcolor, new_record.msg)
        result = super(ColorFormatter, self).format(new_record)
        if self.color_by_level:
            result = "%s%s" % (result, RESET.format(use_color))
        return result


class ColoredStreamHandler(logging.StreamHandler):
    def __init__(self, stream=None, *args, **kwargs):
        super(ColoredStreamHandler, self).__init__(stream=stream)
        self.formatter = ColorFormatter(*args, **kwargs)

    def format(self, record):
        return self.formatter.formatColor(record, use_color=self.stream.isatty())


def setup_argparser(parser):
    parser.add_argument("--log-file", default=None, help="log output to this file in addition to stdout")
    parser.add_argument(
        "--force-color", action="store_true", help="force color output on stdout even if it is not a TTY"
    )

    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument(
        "-v", "--verbose", action="store_true", help="output debugging information such as transmitted bytes"
    )
    logging_group.add_argument("-q", "--quiet", action="store_true", help="only print warnings and errors")


def setup_logging(args, log_fmt, clear_stdout_line=False, color_by_level=False):
    stdout_fmt = ("\r\x1b[K" if clear_stdout_line else "") + log_fmt
    stdout_handler = ColoredStreamHandler(
        stream=sys.stdout, fmt=stdout_fmt, force_color=args.force_color, color_by_level=color_by_level
    )

    if args.verbose is True:
        stdout_handler.setLevel(logging.DEBUG)
    elif args.quiet is True:
        stdout_handler.setLevel(logging.WARN)
    else:
        stdout_handler.setLevel(logging.INFO)

    logging.getLogger().addHandler(stdout_handler)

    if args.log_file is not None:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(ColorFormatter(fmt=log_fmt))
        file_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(file_handler)

    logging.getLogger().setLevel(logging.DEBUG)
