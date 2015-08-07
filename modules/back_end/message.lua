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


----------------------------------------
-- MessageDecoder class, for "Message" statements
--
local MessageDecoder = {}
local MessageDecoder_mt = { __index = MessageDecoder }
setmetatable( MessageDecoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase
--back_end:registerClass("MESSAGE", "MessageDecoder", MessageDecoder)


function MessageDecoder.new(pfield, tag, name, proto, proto_name, tag_dispatch_tbl)
    -- the pfield is actually a ProtoField object for MESSAGE types
    local new_class = DecoderBase.new("MESSAGE", pfield, tag, name)
    new_class["proto"] = proto
    new_class["pname"] = proto_name
    new_class["tags"]  = tag_dispatch_tbl
    setmetatable( new_class, MessageDecoder_mt )
    return new_class
end


function MessageDecoder:decode(decoder)
    -- add the ProtoField first, then using a subtree add Proto, then
    local tree = decoder:addProtoField(self.pfield)
    local old_root = decoder:pushTree(tree)

    -- now add the Proto
    tree = decoder:addProto(self.pfield, self.pname)
    local old_tree = decoder:pushTree(tree)

    -- decode all tags
    decoder:decodeTags(self.tags)

    decoder:popTree(old_tree)
    decoder:popTree(old_root)
end


return MessageDecoder
