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

--[[
    This script is a Lua module (not stand-alone) for protobuf decoding.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

    How it works:

    The Decoder object is created each time a new packet is dissected by a
    Message class' registered proto.dissector. It is then passed around
    through various sub-dissector calls; for example when a Field is decoded,
    or a sub-Message, Group, etc. The Decoder keeps track of some state, such
    as a recursion count to prevent malicious or weird packets from consuming
    too much memory, and a stack of field lengths to prevent overruns (since a
    Message object inside another must not exceed its encoded length, for
    example). It even provides the decoder functions themselves, such as
    decodeVarint32/64 and so on, since those involve variable length fields
    and should not exceed the min length in the stack, etc.

]]

local Struct             = Struct
local Syntax             = require "syntax"
local varint             = require "back_end.varint"
local GenericDecoder     = require "generic.decoder"
local GenericProtoFields = require "generic.proto_fields"
local GenericExperts     = require "generic.experts"

if not Struct then
    error("Wireshark is too old: no Struct library; upgrade to version 1.12 or higher")
end




----------------------------------------
local RECURSION_LIMIT = 100


-- local fixed_struct_fmt = {
--     FIXED32  = "<I4",
--     SFIXED32 = "<i4",
--     -- these return UInt64/Int64 objects
--     FIXED64  = "<E",
--     SFIXED64 = "<e",
--     -- verify these are what we expect, because they might be different
--     -- sizes on different machines:
--     FLOAT    = "<f",
--     DOUBLE   = "<d",
-- }




--------------------------------------------------------------------------------
-- Decoder class
--
local Decoder = {}
local Decoder_mt = { __index = Decoder } 


function Decoder.new(tvbuf, pktinfo, root)
    local new_class = {  -- the new instance
        -- from wireshark
        ["tvbuf"] = tvbuf,
        ["pktinfo"] = pktinfo,

        -- a Lua string of the raw bytes of the Tvb; faster to decode from
        -- this when dealing with varints and such using Struct library than
        -- constantly getting a ByteArray or whatever from the Tvb each time
        ["raw"] = tvbuf:raw(),

        -- pseudo-stack of TreeItems; pushed when sub-tree is added, which
        -- occurs for Message/Group for example, and popped when it returns from it
        ["tree"] = root,

        -- the child tree returned from tree:add() calls, used for tree
        -- push/popping
        ["child_tree"] = nil,

        -- a pseudo-stack of the max lengths for decoding; a new length is pushed
        -- when entering Message/Group; popped on return; must always be <=
        -- previous length in table; "consumed" becomes zero when pushed,
        -- and gets popped back after but with the just-consumed length
        ["limit"] = tvbuf:len(),

        -- the following two will likely not be equal: the cursor is the
        -- absolute offset to the next byte(s) to read from of the whole Tvb,
        -- while the consumed represents how many have been fully decoded of
        -- the current length; for example while decoding the first FIXED32
        -- field of a new Message, right after decoding the key
        -- (tag+wiretype), the cursor would point to the first of the 4 value
        -- bytes of the uint32, while the consumed would still be 0; the
        -- difference of the two would be the length of the key varint in that
        -- case, but generally they can't be compared since cursor is absolute
        -- and consumed is relative to current length
        ["cursor"] = 0,
        --["consumed"] = 0,

        -- whenever we decode a field key, we increase the cursor and decrease
        -- length, but we want to save the location of the key too so that we
        -- can add it to the decode tree; so this does that: it's the cursor
        -- value before we decoded the key
        ["field_start"] = 0,

        -- counts down to 0 as calls/recursions occur
        -- counts up when they return
        ["recursion_count"] = RECURSION_LIMIT,
    }
    setmetatable( new_class, Decoder_mt )
    return new_class
end


function Decoder:getCursor()
    return self.cursor
end


function Decoder:getFieldStart()
    return self.field_start
end


function Decoder:getLimit()
    return self.limit
end


function Decoder:pushLimit(new_limit)
    local old_limit = self.limit
    
    -- it can only get shorter, but not below 0
    -- if it was negative, then use previous limit
    if new_limit >= 0 and new_limit < old_limit then
        self.limit = new_limit
    end
    return old_limit, self.cursor
end


function Decoder:popLimit(old_limit, old_cursor)
    assert(old_limit >= self.limit, "Programming error: popLimit() called with smaller limit")
    -- the previous limit is decreased by amount consumed since
    self.limit = old_limit - (self.cursor - old_cursor)
end


function Decoder:pushTree(child_tree)
    local old_tree = self.tree
    self.tree = child_tree
    return old_tree
end


function Decoder:popTree(old_tree)
    self.tree = old_tree
end


function Decoder:enterRecursion()
    self.recursion_count = self.recursion_count - 1
    return self.recursion_count > 0
end


function Decoder:exitRecursion()
    if self.recursion_count < RECURSION_LIMIT then
        self.recursion_count = self.recursion_count + 1
    end
end


function Decoder:advance(size)
    self.limit = self.limit - size
    assert(self.limit >= 0, "Programming error: limit dropped below 0")
    self.cursor = self.cursor + size
    assert(self.cursor <= (#self.raw + 1), "Programming error: cursor went beyond raw length")
end


local expert_fields = GenericExperts:getFields()
local expert_texts  = GenericExperts:getTexts()
local expert_stops  = GenericExperts:getStops()


function Decoder:addExpert(tree, expert_type, append_text)
    tree = tree or self.tree
    assert(expert_fields[expert_type], "Programming error: invalid expert_type given: " .. expert_type)

    local text = expert_texts[expert_type]
    if append_text then
        text = text .. append_text
    end

    tree:add_proto_expert_info(expert_fields[expert_type], text)

    if expert_stops[expert_type] then
        self.decode_error = true
    end
end


function Decoder:addExpertTvb(tree, expert_type, start, stop, append_text)
    tree = tree or self.tree
    assert(expert_fields[expert_type], "Programming error: invalid expert_type given: " .. expert_type)

    local text = expert_texts[expert_type]
    if append_text then
        text = text .. append_text
    end

    tree:add_tvb_expert_info(expert_fields[expert_type], self.tvb(start,stop), text)

    if expert_stops[expert_type] then
        self.decode_error = true
    end
end


function Decoder:getKey()
    local tag, wiretype, size = varint:decodeKey(self.raw, self.cursor, self.limit)
    if not tag then
        return self:addExpertTvb(nil, "invalid_key", self.cursor, self.limit)
    end

    local wtype = Syntax:getWtypeForWiretype(wiretype)
    if not wtype then
        return self:addExpertTvb(nil, "unknown_wiretype", self.cursor, 1)
    end

    -- move cursor/limit past key
    self:advance(size)

    self.last_wiretype = wiretype

    return tag, wtype, size
end


function Decoder:getWtypeSize(wtype)
    local size = Syntax:getWtypeSize(wtype)
    local length_size = 0

    if size < 0 then
        -- if it's a LENGTH_DELIMITED then we can determine size
        if wtype == "LENGTH_DELIMITED" then
            local value, sz = varint:decode32(self.raw, self.cursor, self.limit)
            if not value then
                return self:addExpertTvb(nil, "invalid_length_delimiter", self.cursor, self.limit)
            end
            self:advance(sz)
            -- note the length-delimited value can legitimately be 0
            size = value
            length_size = sz
        end
    end
    return size, length_size
end


-- called by the Message/Packet class by its wireshark-registered proto.dissector
-- function - i.e., the first/top-level Message, which starts the whole thing
-- off
function Decoder:decode(packet)
    packet:decode(self)
end



-- the big one: invoked by Message and Group types, it decodes
-- all fields until length is reached or END_GROUP
function Decoder:decodeTags(tags, frequency)
    -- for each tag field we find, invoke it's dissector; also keep track of
    -- what we've seen, to detect invalid repetitions of a tag when it's
    -- required/optional/one-of (i.e., not repeated)

    if frequency then
        frequency:reset()
    end

    while self.limit > 0 do
        -- save offset of whole field
        self.field_start = self.cursor

        self.tag, self.last_wtype, self.key_hdr_size = self:getKey()
        if not self.tag then return end

        -- check wiretype for sizing, but not for GROUP/VARINT - for those
        -- make the size the remaining bytes and get the size from the
        -- addFieldXXX() call
        local size, length_size = self:getWtypeSize(self.last_wtype)
        if not size then return end

        self.key_size = self.key_hdr_size + length_size
        self.length_size = length_size

        if self.last_wtype == "END_GROUP" then
            -- assume we are in a group, use the last_wtype to verify later, and return
            -- END_GROUP has no size, right? so not invoking advance()
            return true
        end

        local object = tags[self.tag]
        if object then
            self.frequency = frequency
        else
            -- TODO: expert unknown field
            -- skip it using wiretype info
            object = GenericDecoder
            self.frequency = nil
        end

        -- verify the wiretype matches for the tag's object type
        -- check if not repeated then it's the only time we've seen the tag
        -- check if one-of that we haven't gotten the other one-of tags for the one-of name
        --self:verifyTag(object, tags)

        assert(object.decode, "Programming error: tag in table does not have a dissect function")
        if self:enterRecursion() then
            local limit, cursor = self:pushLimit(size)
            if not object:decode(self, self.tag, self.last_wtype) then
                -- the error should already be handled
                return
            end
            self:exitRecursion()
            self:popLimit(limit, cursor)
            -- verify END_GROUP if previously START_GROUP?
        else
            return self:addExpert(nil, "recursion")
        end
    end

    if frequency then
        frequency:checkMessage()
    end

    return not self.decode_error
end


function Decoder:checkFrequency(tree)
    local ok, expert_type, append_text = self.frequency:checkTag(self.tag)
    if not ok then
        self:addExpert(tree, expert_type, append_text)
    end
end


local pfields = GenericProtoFields:getFields()

-- adds the generic info about fields: key, tag, length, etc.; but this is
-- done after a field is added, so it takes the tree as an argument
function Decoder:addFieldInfo(tree, size)
    -- add the key field and subtree
    local key_tree = tree:add(pfields.key, self.tvbuf(self.field_start, self.key_hdr_size))
    key_tree:add(pfields.tag, self.tvbuf(self.field_start, self.key_hdr_size), self.tag)
    key_tree:add(pfields.wiretype, self.tvbuf(self.field_start,1), self.last_wiretype)

    -- add length delimiter info if there is one
    if self.last_wtype == "LENGTH_DELIMITED" then
        tree:add(pfields.length_delimiter,
                 self.tvbuf(self.field_start + self.key_hdr_size, self.length_size),
                 size)
    end

    tree:add(pfields.length, size):set_generated()

    tree:add(pfields.value, self.tvbuf(self.field_start + self.key_size, size))

    if self.frequency then
        self:checkFrequency(tree)
    end
end


-- for known fixed sizes, we can use the Struct library
function Decoder:addFieldStruct(pfield, fmt, size)
    if size > self.limit then
        return self:addExpert(nil, "too_short")
    end

    -- Struct.unpack() returns two values - this way we only keep the first
    local value = Struct.unpack(fmt, self.raw, self.cursor+1)

    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, size + self.key_size), value)

    self:addFieldInfo(tree, size, value)

    self:advance(size)

    return tree
end


function Decoder:addFieldString(pfield)
    local value = string.sub(self.raw, self.cursor+1, self.cursor + self.limit)

    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, self.limit + self.key_size), value)

    self:addFieldInfo(tree, self.limit, value)

    self:advance(self.limit)

    return tree
end


-- adds the given ProtoField for limit size, advances
function Decoder:addFieldBytes(pfield)
    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, self.limit + self.key_size))
    self:addFieldInfo(tree, self.limit)
    self:advance(self.limit)
    return tree
end


function Decoder:addFieldVarint(pfield, vfunc)
    local value, size = vfunc(varint, self.raw, self.cursor, self.limit)

    if not value then
        return self:addExpertTvb(nil, "invalid_varint", self.cursor, self.limit)
    end

    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, size + self.key_size), value)

    self:addFieldInfo(tree, size, value)

    self:advance(size)

    return tree
end


function Decoder:addFieldVarint32(pfield)
    return self:addFieldVarint(pfield, varint.decode32)
end


function Decoder:addFieldVarintSigned32(pfield)
    return self:addFieldVarint(pfield, varint.decodeSigned32)
end


function Decoder:addFieldVarint64(pfield)
    return self:addFieldVarint(pfield, varint.decode64)
end


function Decoder:addFieldVarintSigned64(pfield)
    return self:addFieldVarint(pfield, varint.decodeSigned64)
end


function Decoder:addFieldBool(pfield)
    local value, size = varint:decode32(self.raw, self.cursor, self.limit)

    if not value then
        return self:addExpertTvb(nil, "invalid_varint", self.cursor, self.limit)
    end

    value = value ~= 0

    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, size + self.key_size), value)

    self:advance(size)

    return tree
end


-- adds the Proto to the tree, pushes the new sub-tree and returns the old,
-- so popTree() must be called later
function Decoder:addProto(pfield, name, separator, is_packet_start)
    separator = separator or ":"

    self.pktinfo.cols.protocol:set(name)

    if is_packet_start then
        self.pktinfo.cols.info:set(name)
    else
        self.pktinfo.cols.info:append(separator .. name)
    end

    local tree = self.tree:add(pfield, self.tvbuf(self.field_start or 0, self.limit))
    tree:set_text(name)

    -- self.cursor does not move, nor does self.limit
    return tree
end


-- just adds a ProtoField of limit size, does not advance cursor
-- this is meant to be used with Group, which does not know the size until later
function Decoder:addField(pfield)
    local tree = self.tree:add(pfield, self.tvbuf(self.field_start, self.limit + self.key_size))

    if self.last_wtype == "START_GROUP" then
        self:addFieldInfo(tree, self.key_size)
    else
        self:addFieldInfo(tree, self.limit)
    end

    return tree
end


return Decoder
