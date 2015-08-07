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
    local tree = decoder:addProto(self.pfield, "Protobuf Message", "", true)

    local root = decoder:pushTree(tree)

    decoder:decodeTags(tags)

    decoder:popTree(root)
    return true
end


return PacketDecoder

