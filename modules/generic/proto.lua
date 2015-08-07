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

assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

local Prefs          = require "prefs"
local PacketDecoder  = require "generic.packet"
local Decoder        = require "back_end.decoder"
local GenericDecoder = require "generic.decoder"
local Fixed32Decoder = require "generic.fixed32"
local Fixed64Decoder = require "generic.fixed64"
local VarintDecoder  = require "generic.varint"
local GroupDecoder   = require "generic.group"
local BytesDecoder   = require "generic.bytes"
local PFieldInfo     = require "generic.pfield_info"


--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local GenericProto = {}


GenericProto.proto = Proto.new("Protobuf", "Google Protobuf Format")



GenericProto.wiretype_valstring = {
    [0] = "VARINT",
    [1] = "FIXED64",
    [2] = "LENGTH_DELIMITED",
    [3] = "START_GROUP",
    [4] = "END_GROUP",
    [5] = "FIXED32",
}


GenericProto.pfields = {
    key      = ProtoField.uint32("protobuf.key", "Key", base.HEX, nil, nil, "Field key section"),
    tag      = ProtoField.uint32("protobuf.tag", "Tag", base.DEC, nil, nil, "Field tag value"),
    wiretype = ProtoField.uint8 ("protobuf.wiretype", "Wire Type", base.DEC, GenericProto.wiretype_valstring, 0x07, "Field wire type value"),
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


-- register the ProtoFields
GenericProto.proto.fields = GenericProto.pfields

-- create the Preferences
Prefs:create(GenericProto.proto)

GenericDecoder:register("FIXED32", Fixed32Decoder.new(GenericProto.pfields.FIXED32))
GenericDecoder:register("FIXED64", Fixed64Decoder.new(GenericProto.pfields.FIXED64))
GenericDecoder:register("VARINT", VarintDecoder.new(GenericProto.pfields.VARINT))
GenericDecoder:register("START_GROUP", GroupDecoder.new(GenericProto.pfields.GROUP))
GenericDecoder:register("LENGTH_DELIMITED", BytesDecoder.new(GenericProto.pfields.LENGTH_BYTES))

PFieldInfo:register("key", GenericProto.pfields.key)
PFieldInfo:register("tag", GenericProto.pfields.tag)
PFieldInfo:register("wiretype", GenericProto.pfields.wiretype)
PFieldInfo:register("length", GenericProto.pfields.length)
PFieldInfo:register("value", GenericProto.pfields.value)
PFieldInfo:register("length_delimiter", GenericProto.pfields.length_delimiter)




local packet_decoder = PacketDecoder.new(GenericProto.proto)

function GenericProto.proto.dissector(tvbuf, pktinfo, root)
    return Decoder.new(tvbuf, pktinfo, root):decode(packet_decoder)
end


DissectorTable.get("udp.port"):add(0, GenericProto.proto)


return GenericProto
