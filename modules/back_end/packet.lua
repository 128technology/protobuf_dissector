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


local Base      = require "back_end.base"
local Frequency = require "back_end.frequency"


--------------------------------------------------------------------------------
-- PacketDecoder class, for "Message" statements but as the whole packet
--
local PacketDecoder = {}
local PacketDecoder_mt = { __index = PacketDecoder }
setmetatable( PacketDecoder, { __index = Base } ) -- make it inherit from Base


function PacketDecoder.new(proto, name, tag_dispatch_tbl)
    -- the pfield is actually a Proto object for MESSAGE types
    local new_class = Base.new("MESSAGE", proto, 0, name)
    new_class["tags"]      = tag_dispatch_tbl
    new_class["frequency"] = Frequency.new(tag_dispatch_tbl)
    setmetatable( new_class, PacketDecoder_mt )
    return new_class
end


function PacketDecoder:decode(decoder)
    local tree = decoder:addProto(self.pfield, self:getName(), "", true)

    local root = decoder:pushTree(tree)

    decoder:decodeTags(self.tags, self.frequency)

    decoder:popTree(root)
    return true
end


return PacketDecoder
