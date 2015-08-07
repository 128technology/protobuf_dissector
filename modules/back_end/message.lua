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

local back_end = _G["back_end"]

----------------------------------------
-- MessageDecoder class, for "Message" statements
--
local MessageDecoder = {}
local MessageDecoder_mt = { __index = MessageDecoder }
setmetatable( MessageDecoder, { __index = back_end.DecoderBase } ) -- make it inherit from DecoderBase
back_end:registerClass("MESSAGE", "MessageDecoder", MessageDecoder)


function MessageDecoder.new(pfield, tag, name, tag_dispatch_tbl)
    -- the pfield is actually a Proto object for MESSAGE types
    local new_class = decoder.DecoderBase:new("MESSAGE", pfield, tag, name)
    new_class["tags"]  = tag_dispatch_tbl
    setmetatable( new_class, MessageDecoder_mt )
    return new_class
end


function MessageDecoder:dissect(decoder)
    local root = decoder:addProto(self.pfield, 0, decoder.length)

    decoder:dissectTags(self.tags)

    decoder:popTree(root)
end
