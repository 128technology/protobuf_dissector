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


assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest version 1.12 or higher")


local GenericExperts = {}


local experts = {
    invalid_key      = {
        abbrev   = "protobuf.key.expert",
        text     = "Protobuf invalid Key",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

    unknown_tag      = {
        abbrev   = "protobuf.field.expert",
        text     = "Protobuf unknown field",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.NOTE,
        stop     = false,
    },

    unknown_wiretype = {
        abbrev   = "protobuf.wiretype.expert",
        text     = "Protobuf unknown Wire Type",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

    invalid_wiretype = {
        abbrev   = "protobuf.field.wiretype.expert",
        text     = "Protobuf field type does not match wiretype",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.WARN,
        stop     = false,
    },

    invalid_length_delimiter = {
        abbrev   = "protobuf.length_delimiter_value.expert",
        text     = "Protobuf invalid Length Delimiter value",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

    invalid_varint   = {
        abbrev   = "protobuf.varint.expert",
        text     = "Protobuf invalid varint",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

    missing_required = {
        abbrev   = "protobuf.field.missing.expert",
        text     = "Protobuf missing a required field(s): ",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.WARN,
        stop     = false,
    },

    multiple_single  = {
        abbrev   = "protobuf.field.oneof.expert",
        text     = "Protobuf field appears more than once but is not 'repeated'",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.WARN,
        stop     = false,
    },

    multiple_oneof   = {
        abbrev   = "protobuf.field.oneof.expert",
        text     = "Protobuf: more than one 'oneof' fields in message",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.WARN,
        stop     = false,
    },

    too_short        = {
        abbrev   = "protobuf.packet.length.expert",
        text     = "Protobuf packet too short",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

    recursion        = {
        abbrev   = "protobuf.decoder.recursion.expert",
        text     = "Protobuf decoder recursed too many times - invalid packet",
        group    = expert.group.PROTOCOL,
        severity = expert.severity.ERROR,
        stop     = true,
    },

}


-- build a table of ProtoExpert fields
local expert_fields = {}
for name, tbl in pairs(experts) do
    expert_fields[name] = ProtoExpert.new(tbl.abbrev, tbl.text, tbl.group, tbl.severity)
end


local expert_texts = {}
for name, tbl in pairs(experts) do
    expert_texts[name] = tbl.text
end


local expert_stops = {}
for name, tbl in pairs(experts) do
    expert_stops[name] = tbl.stop
end


function GenericExperts:getFields()
    return expert_fields
end


function GenericExperts:getTexts()
    return expert_texts
end


function GenericExperts:getStops()
    return expert_stops
end


return GenericExperts
