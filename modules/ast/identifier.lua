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

local Base = require "ast.base"


----------------------------------------
-- The Identifier class, cannot be scoped
-- this is used for things like messageName, enumName, etc.
-- grammar: ident
local Identifier = {}
local Identifier_mt = { __index = Identifier } -- base class
setmetatable( Identifier, { __index = Base } ) -- inherit from Base


function Identifier.parse(st, idx)
    dassert(#st >= idx, "Programming error: Identifier subtable too short", "\nToken list:", st)

    if st[idx]:canBeIdentifier() then
        -- change it to be an identifier
        st[idx]:setTtype("IDENTIFIER")
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
    derror("Programming error: Identifier:resolve() invoked")
end


function Identifier:display()
    return tostring(self.value)
end


return Identifier
