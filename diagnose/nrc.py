#!/usr/bin/python
# vim:tw=100:sw=4:ts=4:sts=4:et
# pylint: disable=invalid-name,missing-docstring,too-few-public-methods,too-many-lines

# Copyright 2016-2017 BMW Group
# Author: Kjell Braden

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from diagnose import UdsError

CODES = {
    b"\x10": "General_Reject",
    b"\x11": "Service_Not_Supported",
    b"\x12": "Sub_Function_Not_Supported",
    b"\x13": "Incorrect_Message_Length_Or_Invalid_Format",
    b"\x14": "Response_Too_Long",
    b"\x21": "Busy_Repeat_Request",
    b"\x22": "Conditions_Not_Correct",
    b"\x24": "Request_Sequence_Error",
    b"\x25": "No_Response_From_Subnet_Component",
    b"\x26": "Failure_Prevents_Execution_of_Requested_Action",
    b"\x31": "Request_Out_Of_Range",
    b"\x33": "Security_Access_Denied",
    b"\x35": "Invalid_Key",
    b"\x36": "Exceeded_Number_of_Attempts",
    b"\x37": "Required_Time_Delay_Not_Expired",
    b"\x38": "ISO_15764_Secured_Data_Transmission_Error_38",
    b"\x39": "ISO_15764_Secured_Data_Transmission_Error_39",
    b"\x3a": "ISO_15764_Secured_Data_Transmission_Error_3a",
    b"\x3b": "ISO_15764_Secured_Data_Transmission_Error_3b",
    b"\x3c": "ISO_15764_Secured_Data_Transmission_Error_3c",
    b"\x3d": "ISO_15764_Secured_Data_Transmission_Error_3d",
    b"\x3e": "ISO_15764_Secured_Data_Transmission_Error_3e",
    b"\x3f": "ISO_15764_Secured_Data_Transmission_Error_3f",
    b"\x40": "ISO_15764_Secured_Data_Transmission_Error_40",
    b"\x41": "ISO_15764_Secured_Data_Transmission_Error_41",
    b"\x42": "ISO_15764_Secured_Data_Transmission_Error_42",
    b"\x43": "ISO_15764_Secured_Data_Transmission_Error_43",
    b"\x44": "ISO_15764_Secured_Data_Transmission_Error_44",
    b"\x45": "ISO_15764_Secured_Data_Transmission_Error_45",
    b"\x46": "ISO_15764_Secured_Data_Transmission_Error_46",
    b"\x47": "ISO_15764_Secured_Data_Transmission_Error_47",
    b"\x48": "ISO_15764_Secured_Data_Transmission_Error_48",
    b"\x49": "ISO_15764_Secured_Data_Transmission_Error_49",
    b"\x4a": "ISO_15764_Secured_Data_Transmission_Error_4a",
    b"\x4b": "ISO_15764_Secured_Data_Transmission_Error_4b",
    b"\x4c": "ISO_15764_Secured_Data_Transmission_Error_4c",
    b"\x4d": "ISO_15764_Secured_Data_Transmission_Error_4d",
    b"\x4e": "ISO_15764_Secured_Data_Transmission_Error_4e",
    b"\x4f": "ISO_15764_Secured_Data_Transmission_Error_4f",
    b"\x70": "Upload_Download_Not_Accepted",
    b"\x71": "Transfer_Data_Suspended",
    b"\x72": "General_Programming_Failure",
    b"\x73": "Wrong_Block_Sequence_Counter",
    b"\x78": "Response_Pending",
    b"\x7e": "Sub_Function_Not_Supported_in_Active_Session",
    b"\x7f": "Service_Not_Supported_in_Active_Session",
    b"\x81": "RPM_Too_High",
    b"\x82": "RPM_Too_Low",
    b"\x83": "Engine_Is_Running",
    b"\x84": "Engine_Is_Not_Running",
    b"\x85": "Engine_Run_Time_Too_Low",
    b"\x86": "Temperature_Too_High",
    b"\x87": "Temperature_Too_Low",
    b"\x88": "Vehicle_Speed_Too_High",
    b"\x89": "Vehicle_Speed_Too_Low",
    b"\x8a": "Throttle/Pedal_Too_High",
    b"\x8b": "Throttle/Pedal_Too_Low",
    b"\x8c": "Transmission_Range_Not_In_Neutral",
    b"\x8d": "Transmission_Range_Not_In_Gear",
    b"\x8f": "Brake_Pedal_not_pressed_or_not_applied",
    b"\x90": "Shifter_Lever_Not_In_Park",
    b"\x91": "Torque_Converter_Clutch_Locked",
    b"\x92": "Voltage_Too_High",
    b"\x93": "Voltage_Too_Low",
}

exception = {}


class NRC(UdsError):
    code = b""

    def __init__(self, response, source=None):
        super(NRC, self).__init__(None, source=None)
        self.response = response

    def __repr__(self):
        return "<%s>" % self.__class__.__name__

    def __str__(self):
        return self.__class__.__name__


for c, name in CODES.items():
    E = type(str(name), (NRC,), {"code": c})
    globals()[name] = E
    exception[c] = E
