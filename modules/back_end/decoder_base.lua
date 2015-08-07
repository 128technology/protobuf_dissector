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

local Base = require "back_end.base"

--------------------------------------------------------------------------------
-- The DecoderBase base class, from which others derive
--
-- All DecoderBase have a type.
--
local DecoderBase = {}
local DecoderBase_mt = { __index = DecoderBase }
setmetatable( DecoderBase, { __index = Base } ) -- inherit from Base


-- ttype is the same as for AST classes; pfield is the registered wireshark ProtoField,
-- or Proto in the case of Message types; tag is the tag number; name is the Identifier
-- as a string
function DecoderBase.new(ttype, pfield, tag, name)
    local new_class = Base.new(ttype) -- the new instance
    new_class["pfield"] = pfield
    new_class["tag"] = tag
    new_class["name"] = name
    setmetatable( new_class, DecoderBase_mt )
    return new_class
end


function DecoderBase:getPField()
    return self.pfield
end


function DecoderBase:getTag()
    return self.tag
end

function DecoderBase:getName()
    return self.name
end


return DecoderBase
