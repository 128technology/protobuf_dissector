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

local Base = require "ast.base"
local syntax = require "syntax"


----------------------------------------
-- The Identifier class, cannot be scoped
-- this is used for things like messageName, enumName, etc.
-- grammar: ident
local Identifier = {}
local Identifier_mt = { __index = Identifier } -- base class
setmetatable( Identifier, { __index = Base } ) -- inherit from Base


function Identifier.parse(st, idx)
    assert(#st >= idx, "Identifier subtable too short")

    if syntax:canTokenBeIdentifier(st[idx]) then
        -- change it to be an identifier
        st[idx].ttype = "IDENTIFIER"
        return st[idx].value, idx+1
    end
end


function Identifier.protected_new(value)
    local new_class = Base.new("IDENTIFIER") -- the new instance
    new_class["value"] = value
    setmetatable( new_class, Identifier_mt )
    return new_class
end


function Identifier.new(st, idx)
    local value, new_idx = Identifier.parse(st, idx)
    return Identifier.protected_new(value), new_idx
end


function Identifier:isScoped()
    return false
end


function Identifier:getValue()
    return self.value
end


function Identifier:size()
    return 1
end


function Identifier:resolve()
    error("Programming error: Identifier:resolve() invoked")
end


function Identifier:display()
    return tostring(self.value)
end


return Identifier
