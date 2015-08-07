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


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror

local Base = require "generic.base"


----------------------------------------
-- GroupDecoder class, for group fields
--
local GroupDecoder = {}
local GroupDecoder_mt = { __index = GroupDecoder }
setmetatable( GroupDecoder, { __index = Base } ) -- make it inherit from Base



function GroupDecoder.new(pfield)
    local new_class = Base.new("START_GROUP", pfield)
    setmetatable( new_class, GroupDecoder_mt )
    return new_class
end


local tags = {}

function GroupDecoder:decode(decoder, tag)
    dprint2("GroupDecoder:decode() called")

    local start = decoder:getFieldStart()

    local tree = decoder:addField(self.pfield)

    local root = decoder:pushTree(tree)

    decoder:decodeTags(tags)

    -- TODO: verify last_wtype == "END_GROUP"

    tree:set_len(decoder:getCursor() - start)

    decoder:popTree(root)
    return true
end


return GroupDecoder
