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

local DecoderBase = require "back_end.decoder_base"


--------------------------------------------------------------------------------
-- PacketDecoder class, for "Message" statements but as the whole packet
--
local PacketDecoder = {}
local PacketDecoder_mt = { __index = PacketDecoder }
setmetatable( PacketDecoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase


function PacketDecoder.new(proto, tag_dispatch_tbl)
    -- the pfield is actually a Proto object for MESSAGE types
    local new_class = DecoderBase.new("MESSAGE", proto, 0, nil)
    new_class["tags"]  = tag_dispatch_tbl
    setmetatable( new_class, PacketDecoder_mt )
    return new_class
end


function PacketDecoder:decode(decoder)
    local tree = decoder:addProto(self.pfield, "", true)

    local root = decoder:pushTree(tree)

    decoder:decodeTags(self.tags)

    decoder:popTree(root)
end


return PacketDecoder
