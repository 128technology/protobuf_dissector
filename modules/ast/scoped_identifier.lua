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

local Identifier = require "ast.identifier"
local Syntax     = require "syntax"


----------------------------------------
-- The ScopedIdentifier class, may be scoped
-- this is used for things like fullIdent, messageType, enumType
-- grammar: ["."] {ident "."} ident
local ScopedIdentifier = {}
local ScopedIdentifier_mt = { __index = ScopedIdentifier }
setmetatable( ScopedIdentifier, { __index = Identifier } ) -- inherit from Identifier


-- go through finding [.] ident ([.] ident)*
-- save their actual tokens into a table as our value
function ScopedIdentifier.parse(st, idx)
    dassert(#st >= idx, "Identifier subtable too short")

    local t = {}

    -- could have leading period for global scope
    if st[idx].ttype == "PERIOD" then
        -- save the token and keep going
        t[#t+1] = st[idx]
        idx = idx + 1
        dassert(st[idx], "Globally scoped identifier value missing identifier")
    end

    while idx <= #st do
        dassert(st[idx]:canBeIdentifier(), st[idx], "ScopedIdentifier value is not an identifier:", st[idx].value)
        -- make it an IDENTIFIER and save it
        st[idx].ttype = "IDENTIFIER"
        t[#t+1] = st[idx]
        idx = idx + 1

        -- see if next one is a period
        if idx < #st and st[idx].ttype == "PERIOD" then
            -- save it and go around again
            t[#t+1] = st[idx]
            idx = idx + 1
        else
            -- we're done
            return t, idx
        end
    end

    -- we're done
    return t, idx
end


function ScopedIdentifier.new(st, idx)
    local value, new_idx = ScopedIdentifier.parse(st, idx)
    local new_class = Identifier.protected_new(value)
    setmetatable( new_class, ScopedIdentifier_mt )
    return new_class, new_idx
end


function ScopedIdentifier:isGlobalScope()
    return self.value[1].ttype == "PERIOD"
end


function ScopedIdentifier:isScoped()
    for _, token in self.value do
        if token.ttype == "PERIOD" then
            return true
        end
    end
    dassert(#self.value == 1, "Programming error: ScopedIdentifier has multiple values without a '.' PERIOD")
    return false
end


function ScopedIdentifier:getValue(portion_idx)
    local values = self.value

    if not portion_idx then
        -- behave like Identifier
        dassert(not self:isScoped(), "Programming error: getValue() called without index on ScopedIdentifier")
        return values[#values].value
    end

    -- give back requested portion
    local idx = (portion_idx * 2) - 1
    if self:isGlobalScope() then
        -- offset for the global scope's period
        idx = idx +1
    end

    return idx <= #values and values[idx].value or nil
end


function ScopedIdentifier:size()
    local size = #self.value
    if self:isGlobalScope() then
        size = size - 1
    end
    return (size + 1) / 2
end


function ScopedIdentifier:resolve(namespace)
    if self:isGlobalScope() then
        return namespace:findAbsoluteDeclaration(self)
    else
        return namespace:findRelativeDeclaration(self)
    end
end


function ScopedIdentifier:display()
    return Syntax:concatTokenValues(self.value)
end


return ScopedIdentifier
