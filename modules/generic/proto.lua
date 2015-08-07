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


local Prefs              = require "prefs"
local PacketDecoder      = require "generic.packet"
local Decoder            = require "back_end.decoder"
local GenericDecoder     = require "generic.decoder"
local Fixed32Decoder     = require "generic.fixed32"
local Fixed64Decoder     = require "generic.fixed64"
local VarintDecoder      = require "generic.varint"
local GroupDecoder       = require "generic.group"
local BytesDecoder       = require "generic.bytes"
local GenericProtoFields = require "generic.proto_fields"
local GenericExperts     = require "generic.experts"


--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local GenericProto = {}


GenericProto.proto = Proto.new("Protobuf", "Google Protobuf Format")

local pfields = GenericProtoFields:getFields()

-- register the ProtoFields and Experts
GenericProto.proto.fields = pfields
GenericProto.proto.experts = GenericExperts:getFields()


-- create the Preferences
Prefs:create(GenericProto.proto)


GenericDecoder:register("FIXED32", Fixed32Decoder.new(pfields.FIXED32))
GenericDecoder:register("FIXED64", Fixed64Decoder.new(pfields.FIXED64))
GenericDecoder:register("VARINT", VarintDecoder.new(pfields.VARINT))
GenericDecoder:register("START_GROUP", GroupDecoder.new(pfields.GROUP))
GenericDecoder:register("LENGTH_DELIMITED", BytesDecoder.new(pfields.LENGTH_BYTES))




local packet_decoder = PacketDecoder.new(GenericProto.proto)

function GenericProto.proto.dissector(tvbuf, pktinfo, root)
    return Decoder.new(tvbuf, pktinfo, root):decode(packet_decoder)
end


DissectorTable.get("udp.port"):add(0, GenericProto.proto)


return GenericProto
