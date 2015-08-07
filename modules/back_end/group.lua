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


----------------------------------------
-- GroupDecoder class, for "Message" statements
--
local GroupDecoder = {}
local GroupDecoder_mt = { __index = GroupDecoder }
setmetatable( GroupDecoder, { __index = Base } ) -- make it inherit from Base


function GroupDecoder.new(pfield, tag, name, tag_dispatch_tbl, label, oneof_name)
    local new_class = Base.new("START_GROUP", pfield, tag, name, label, oneof_name)
    new_class["tags"]      = tag_dispatch_tbl
    new_class["frequency"] = Frequency.new(tag_dispatch_tbl)
    setmetatable( new_class, GroupDecoder_mt )
    return new_class
end


function GroupDecoder:decode(decoder)
    -- add the ProtoField first, then using a subtree add Proto, then
    local tree = decoder:addField(self.pfield, self.name)
    local old_root = decoder:pushTree(tree)

    -- decode all tags
    decoder:decodeTags(self.tags, self.frequency)

    decoder:popTree(old_root)
    return true
end


return GroupDecoder
