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


--------------------------------------------------------------------------------
-- The Base base class, from which others derive
--
-- All Bases have a type.
--
local Base = {}
local Base_mt = { __index = Base }


-- ttype is the same as for AST classes; pfield is the registered wireshark ProtoField,
-- or Proto in the case of Message types; tag is the tag number; name is the Identifier
-- as a string
function Base.new(ttype, pfield, tag, name, label, oneof_name)
    local new_class = {  -- the new instance
        ["ttype"]      = ttype,
        ["pfield"]     = pfield,
        ["tag"]        = tag,
        ["name"]       = name,
        ["label"]      = label,
        ["oneof_name"] = oneof_name,
    }
    setmetatable( new_class, Base_mt )
    return new_class
end


function Base:getType()
    return self.ttype
end


function Base:getPField()
    return self.pfield
end


function Base:getTag()
    return self.tag
end


function Base:getName()
    return self.name
end


function Base:getLabel()
    return self.label
end


function Base:getOneofName()
    return self.oneof_name
end


return Base
