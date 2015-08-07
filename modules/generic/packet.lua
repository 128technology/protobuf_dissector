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
-- PacketDecoder class, for whole packets
--
local PacketDecoder = {}
local PacketDecoder_mt = { __index = PacketDecoder }
setmetatable( PacketDecoder, { __index = Base } ) -- make it inherit from Base


function PacketDecoder.new(pfield)
    local new_class = Base.new("MESSAGE", pfield)
    setmetatable( new_class, PacketDecoder_mt )
    return new_class
end


local tags = {}

function PacketDecoder:decode(decoder)
    dprint2("PacketDecoder:decode() called")

    local tree = decoder:addProto(self.pfield, "Protobuf Message", "", true)

    local root = decoder:pushTree(tree)

    decoder:decodeTags(tags)

    decoder:popTree(root)
    return true
end


return PacketDecoder

