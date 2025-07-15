#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import binascii
import ctypes
import sys
import time

import construct
import six

# ugly hack to make construct not use a special case for displaying byte string types
# we use PrintHex for this
construct.lib.container.stringtypes = (six.text_type,)

try:
    long
except NameError:
    long = int  # pylint: disable=redefined-builtin

clock = time.monotonic if sys.version_info[:2] >= (3, 3) else time.time


def unhex(s):
    return binascii.unhexlify(s.replace(" ", ""))


def enhex(s, sep=" "):
    # (bytes) -> str
    if not isinstance(s, bytes):
        s = bytes(s)
    return sep.join("%02x" % c for c in six.iterbytes(s))


def singleton(cls):
    return cls()


def strtobool(s):
    yes = set(("yes", "on", "true", "y", "1"))
    no = set(("no", "off", "false", "n", "0"))
    ls = s.lower()
    if ls in yes:
        return True
    if ls in no:
        return False
    raise ValueError("%r not parsable as bool" % s)


class Structure(ctypes.BigEndianStructure):
    _pack_ = 1
    _defaults_ = {}
    _formats_ = {}

    def __init__(self, **kwargs):
        # prime data with defaults first
        keys = dict(self._defaults_)
        # then update values with given parameters
        keys.update(kwargs)
        ctypes.BigEndianStructure.__init__(self, **keys)

    @classmethod
    def unpack(cls, data):
        # initialize empty structure
        obj = cls()

        # copy data over
        if len(data) != ctypes.sizeof(cls):
            raise ValueError(
                "wrong length to parse to %s: %d given, %d required" % (cls.__name__, len(data), ctypes.sizeof(cls))
            )

        ctypes.memmove(ctypes.addressof(obj), data, ctypes.sizeof(cls))
        return obj

    def pack(self):
        return memoryview(self).tobytes()

    def _format(self, field):
        DEFAULT_FORMAT = "r"
        fmt = "%s=%" + self._formats_.get(field, DEFAULT_FORMAT)
        return fmt % (field, getattr(self, field))

    def __repr__(self):
        return "<%s(%s)>" % (self.__class__.__name__, ", ".join(self._format(f[0]) for f in self._fields_))


class EnumItem(object):
    def __init__(self, enum_type, value, name):
        self.enum_type = enum_type
        self.enum_value = value
        self._name = name

    def __str__(self):
        return self._name

    def value(self):
        return self.enum_value

    def __repr__(self):
        return "<%s(%s=%r)>" % (self.enum_type.__name__, self._name, self.enum_value)

    def __hash__(self):
        return hash((self.enum_type, self.enum_value))

    def __eq__(self, other):
        return (
            isinstance(other, self.__class__)
            and self.enum_type == other.enum_type
            and self.enum_value == other.enum_value
        )

    def __ne__(self, other):
        return not self == other


class EnumMeta(type):
    def __getattr__(cls, name):
        for k, v in cls.value_table.items():
            if name == v:
                return EnumItem(cls, k, v)
        raise KeyError("unknown element in %s: %r" % (cls.__name__, name))

    def __getitem__(cls, value):
        default = "%s_0x%s" % (cls.default, enhex(value, sep=""))
        return EnumItem(cls, value, cls.value_table.get(value, default))

    def names(cls):
        return cls.value_table.values()


class ConstructEnum(construct.Adapter):
    subcon = None
    value_table = {}
    default = None

    def __init__(self):
        super(ConstructEnum, self).__init__(self.subcon)

    def _encode(self, obj, _):
        if isinstance(obj, six.text_type):
            print("_encode(%r) 1= %r" % (obj, getattr(self, obj)))
            obj = getattr(self, obj)
        cls = self.__class__
        if isinstance(obj, EnumItem) and obj.enum_type == cls:
            print("_encode(%r) 2= %r" % (obj, obj.value()))
            return obj.value()
        raise TypeError("this enum %r can't encode %r" % (cls, obj))

    def _decode(self, obj, _):
        return self[obj]

    def __getattr__(self, name):
        cls = self.__class__
        for k, v in self.value_table.items():
            if name == v:
                return EnumItem(cls, k, v)
        raise KeyError("unknown element in %s: %r" % (cls.__name__, name))

    def __getitem__(self, value):
        cls = self.__class__
        default = "%s_0x%s" % (cls.default, enhex(value, sep=""))
        return EnumItem(cls, value, cls.value_table.get(value, default))

    def names(self):
        cls = self.__class__
        return cls.value_table.values()


class HexBytes(bytes):
    def __new__(cls, value, *args, **kwargs):  # pylint: disable=unused-argument
        return super(HexBytes, cls).__new__(cls, value)

    def __init__(self, value, sep=" "):  # pylint: disable=unused-argument
        super(HexBytes, self).__init__()
        self.sep = sep

    def __str__(self):
        return enhex(self, sep=self.sep)

    def __repr__(self):
        return "b'%s'" % ("".join("\\x%02x" % c for c in six.iterbytes(self)))


class HexInt(long):
    def __new__(cls, value, *args, **kwargs):  # pylint: disable=unused-argument
        return super(HexInt, cls).__new__(cls, value)

    def __init__(self, value, length_in_bytes=0, sep=" "):  # pylint: disable=unused-argument
        super(HexInt, self).__init__()
        self.length = length_in_bytes * 2  # number of characters is twice the length in bytes
        self.sep = sep

    def __str__(self):
        return ("0x%%0%dx" % self.length) % self

    __repr__ = __str__


class PrintHex(construct.Adapter):
    def __init__(self, subcon, sep=" "):
        super(PrintHex, self).__init__(subcon)
        self.sep = sep

    def _encode(self, obj, context):
        return obj

    def _decode(self, obj, context):
        if isinstance(obj, bytes):
            return HexBytes(obj, sep=self.sep)
        elif isinstance(obj, six.integer_types):
            length = self.sizeof(context)
            return HexInt(obj, length_in_bytes=length, sep=self.sep)
        else:
            raise NotImplementedError("PrintHex can only adapt bytes- or integer-types")


def bitarray(bytestring):
    return list((byte & (1 << (7 - bit))) != 0 for byte in six.iterbytes(bytestring) for bit in range(8))


def bitindex(bits, offset, length):
    bits = bits[offset : offset + length]
    value = 0
    for bitvalue, bit in enumerate(reversed(bits)):
        value |= bit << bitvalue
    return value


def chunks(nextSection, maxlength):
    n = max(1, maxlength)
    return (nextSection[i : i + n] for i in range(0, len(nextSection), n))
