----------------------------------------
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, 128 Technology, Inc.
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local M = {}


M.proto = Proto.new("Protobuf", "Google Protobuf Format")


M.wire_type_handler = {
    "FIXED32"             = function() return 4 end,
    "FIXED64"             = function() return 8 end,
    "VARINT"              = function(tvbuf, offset)
                                local _, consumed = decodeVarint64(tvbuf, offset)
                                return consumed
                            end,
    "LENGTH_DELIMITED"    = function(tvbuf, offset)
                                local length, consumed = decodeVarint32(tvbuf, offset)
                                return length + consumed
                            end,
    "START_GROUP"         = function(tvbuf, offset, recurse_count)
                                return 
                            end,
}



M.wire_type_valstring = {
    [0] = "VARINT",
    [1] = "FIXED64",
    [2] = "LENGTH_DELIMITED",
    [3] = "START_GROUP",
    [4] = "END_GROUP",
    [5] = "FIXED32",
}


M.pfields = {
    key       = ProtoField.uint64("protobuf.key", "Key", base.HEX, nil, nil, "Field key section"),
    tag       = ProtoField.uint64("protobuf.tag", "Tag", base.DEC, nil, nil, "Field tag value"),
    wire_type = ProtoField.uint8 ("protobuf.wire_type", "Wire Type", base.DEC, M.wire_type_valstring, 0x03, "Field wire type value"),
    length    = ProtoField.uint64("protobuf.length", "Length", base.DEC, nil, nil, "Field length"),
}


-- register the ProtoFields
M.proto.fields = M.pfields


-- The dissector that gets called by every Message, and invokes the appropriate dissector
-- this is indirectly recursive: if a Message is in a Message.
-- There is a Decoder object passed around as well, which keeps track of
-- things between levels of calls/recursion. For example it prevents too
-- many levels of recursion, keeps track of max lengths, etc.
M.dissector = function(get_dissector, tvbuf, pktinfo, root)
    local pktlen = tvbuf:len()
    local offset = 0

    while pktlen - offset > 0 do
        local key, consumed = decodeVarint32(tvbuf, offset)
        -- TODO: expert info if key varint malformed

        local tag, wire_type = decodeKey(key)

        if not M.wire_type_valstring[wire_type] then
            -- TODO: expert info if wiretype unknown
        else
            consumed = consumed + M.wire_type_valstring[wire_type]
        end

        local field_dissector
        if type(get_dissector) == "table" then
            field_dissector = get_dissector[tag]
        elseif type(get_dissector) == "function" then
            field_dissector = get_dissector(tag)
        end

        if not field_dissector then
            -- TODO: expert info for unknown tag
        else
            local dissected, field_consumed = field_dissector(tag, wire_type, tvbuf, offset, offset + consumed, pktinfo, root)
        end

        offset = offset + consumed + field_consumed

    end
end


return M
