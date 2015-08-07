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

local Base = require "back_end.base"


----------------------------------------
-- MessageDecoder class, for "Message" statements
--
local MessageDecoder = {}
local MessageDecoder_mt = { __index = MessageDecoder }
setmetatable( MessageDecoder, { __index = Base } ) -- make it inherit from Base


function MessageDecoder.new(pfield, tag, name, proto, proto_name, tag_dispatch_tbl, label, oneof_name)
    -- the pfield is actually a ProtoField object for MESSAGE types
    local new_class = Base.new("MESSAGE", pfield, tag, name, label, oneof_name)
    new_class["proto"] = proto
    new_class["pname"] = proto_name
    new_class["tags"]  = tag_dispatch_tbl
    setmetatable( new_class, MessageDecoder_mt )
    return new_class
end


function MessageDecoder:decode(decoder)
    -- add the ProtoField first, then using a subtree add Proto, then
    local tree = decoder:addField(self.pfield)
    local old_root = decoder:pushTree(tree)

    -- now add the Proto
    tree = decoder:addProto(self.proto, self.pname)
    local old_tree = decoder:pushTree(tree)

    -- decode all tags
    decoder:decodeTags(self.tags)

    decoder:popTree(old_tree)
    decoder:popTree(old_root)
    return true
end


return MessageDecoder
