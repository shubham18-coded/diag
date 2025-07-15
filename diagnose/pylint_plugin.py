#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import print_function

import astroid
from astroid import MANAGER

CON_ENUM_CLS = "diagnose.tools.ConstructEnum"
STRUCT_CLS = "diagnose.tools.Structure"


def register(lint):
    def transform_enum(cls):
        for d in cls.igetattr("value_table"):
            if not isinstance(d, astroid.Dict):
                # ignore non-dicts
                break
            names_func = cls.metaclass().getattr("names")[0]
            # bind function in meta class to actual class
            cls.set_local("names", astroid.BoundMethod(names_func, cls))
            # create EnumItem instances for each defined value
            for _, v in d.items:
                attr = v.itered()
                classdef_item = cls.metaclass().lookup("EnumItem")[1][0]
                cls.set_local(attr, classdef_item.instantiate_class())
            break
        else:
            lint.add_message("no-member", node=cls, args=(cls.display_type(), cls.name, "value_table"))

    MANAGER.register_transform(
        astroid.ClassDef,
        transform_enum,
        lambda n: n.metaclass() and n.metaclass().qname() == "diagnose.tools.EnumMeta",
    )

    def transform_construct_enum(cls):
        superclass = [a for a in cls.ancestors() if a.qname() == CON_ENUM_CLS][0]
        found = False
        for d in cls.igetattr("value_table"):
            if d.frame() == superclass:
                break
            if not isinstance(d, astroid.Dict):
                # ignore non-dicts
                break
            for _, v in d.items:
                # create EnumItem instances for each defined value
                found = True
                attr = v.itered()
                classdef_item = superclass.lookup("EnumItem")[1][0]
                cls.set_local(attr, classdef_item.instantiate_class())
            break
        if not found:
            lint.add_message("no-member", node=cls, args=(cls.display_type(), cls.name, "value_table"))

    MANAGER.register_transform(
        astroid.ClassDef, transform_construct_enum, lambda n: CON_ENUM_CLS in (a.qname() for a in n.ancestors())
    )

    def transform_structure(cls):
        for d in cls.igetattr("_fields_"):
            if not isinstance(d, astroid.List):
                # ignore non-lists
                break

            for v in d.itered():
                field_desc = list(v.itered())
                field_name = field_desc[0].itered()
                # set the field to constant zero
                cls.set_local(field_name, astroid.const_factory(0))
            break
        else:
            lint.add_message("no-member", node=cls, args=(cls.display_type(), cls.name, "value_table"))

    MANAGER.register_transform(
        astroid.ClassDef, transform_structure, lambda n: STRUCT_CLS in (a.qname() for a in n.ancestors())
    )
    MANAGER.register_transform(astroid.Module, transform_nrc, lambda n: n.qname() == "diagnose.nrc")
    MANAGER.register_failed_import_hook(failed_import_hook)


def transform_nrc(mod):
    for d in mod.igetattr("CODES"):
        for _, v in d.items:
            attr = v.itered()
            classdef_item = mod.lookup("NRC")[1][0]
            new_class = astroid.ClassDef(attr, None)
            new_class.bases = [classdef_item]
            new_class.parent = mod
            mod.frame().set_local(attr, new_class)


def failed_import_hook(name):
    for p in ("requests.packages.",):
        if name.startswith(p):
            return MANAGER.ast_from_module_name(name[len(p) :])
    raise astroid.exceptions.AstroidBuildingException
