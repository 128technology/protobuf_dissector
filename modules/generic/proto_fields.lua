----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------


-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local GenericProtoFields = {}


local wiretype_valstring = {
    [0] = "VARINT",
    [1] = "FIXED64",
    [2] = "LENGTH_DELIMITED",
    [3] = "START_GROUP",
    [4] = "END_GROUP",
    [5] = "FIXED32",
}


local proto_pfields = {
    key      = ProtoField.uint32("protobuf.key", "Key", base.HEX, nil, nil, "Field key section"),
    tag      = ProtoField.uint32("protobuf.tag", "Tag", base.DEC, nil, nil, "Field tag value"),
    wiretype = ProtoField.uint8 ("protobuf.wiretype", "Wire Type", base.DEC, wiretype_valstring, 0x07, "Field wire type value"),
    length   = ProtoField.uint32("protobuf.length", "Length", base.DEC, nil, nil, "Field length"),
    value    = ProtoField.bytes ("protobuf.value", "Value", base.HEX, nil, nil, "Field value bytes"),
    length_delimiter = ProtoField.uint32("protobuf.length_delimiter_value", "Length Delimiter Value", base.DEC, nil, nil, "Field length-delimited length value"),

    -- following are for wiretypes for unknown fields
    FIXED32  = ProtoField.uint32("protobuf.fixed32", "Fixed32 Value", base.DEC, nil, nil, "Unknown Fixed32 Field value"),
    FIXED64  = ProtoField.uint64("protobuf.fixed64", "Fixed64 Value", base.DEC, nil, nil, "Unknown Fixed64 Field value"),
    VARINT   = ProtoField.uint64("protobuf.varint", "Varint Value", base.DEC, nil, nil, "Unknown Varint Field value"),
    GROUP    = ProtoField.bytes ("protobuf.group", "Group", base.NONE, nil, nil, "Unknown Group Field"),
    LENGTH_BYTES = ProtoField.bytes("protobuf.length_delimited_bytes", "Length Delimited Bytes", base.HEX, nil, nil, "Unknown Length Delimited Field"),
}


function GenericProtoFields:getFields()
    return proto_pfields
end


return GenericProtoFields
