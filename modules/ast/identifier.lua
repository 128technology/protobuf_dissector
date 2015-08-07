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

require "ast.base"

local ast = _G["ast"]
local syntax = _G["syntax"]


----------------------------------------
-- The Identifier class, cannot be scoped
-- this is used for things like messageName, enumName, etc.
-- grammar: ident
local Identifier = {}
local Identifier_mt = { __index = Identifier } -- base class
setmetatable( Identifier, { __index = ast.Base } ) -- inherit from Base
ast:registerClass(nil, "Identifier", Identifier)


function Identifier.parse(st, idx)
    assert(#st >= idx, "Identifier subtable too short")

    if syntax:canTokenBeIdentifier(st[idx]) then
        -- change it to be an identifier
        st[idx].ttype = "IDENTIFIER"
        return st[idx].value, idx+1
    end
end


function Identifier:protected_new(value)
    local new_class = ast.Base:new("IDENTIFIER") -- the new instance
    new_class["value"] = value
    setmetatable( new_class, Identifier_mt )
    return new_class
end


function Identifier:new(st, idx)
    local value, new_idx = self.parse(st, idx)
    return self:protected_new(value), new_idx
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



----------------------------------------
-- The ScopedIdentifier class, may be scoped
-- this is used for things like fullIdent, messageType, enumType
-- grammar: ["."] {ident "."} ident
local ScopedIdentifier = {}
local ScopedIdentifier_mt = { __index = ScopedIdentifier }
setmetatable( ScopedIdentifier, Identifier_mt ) -- inherit from Identifier
ast:registerClass(nil, "ScopedIdentifier", ScopedIdentifier)


-- go through finding [.] ident ([.] ident)*
-- save their actual tokens into a table as our value
function ScopedIdentifier.parse(st, idx)
    assert(#st >= idx, "Identifier subtable too short")

    local t = {}

    -- could have leading period for global scope
    if st[idx].ttype == "PERIOD" then
        -- save the token and keep going
        t[#t+1] = st[idx]
        idx = idx + 1
        assert(st[idx], "Globally scoped identifier value missing identifier")
    end

    while idx <= #st do
        assert(syntax:canTokenBeIdentifier(st[idx]), "ScopedIdentifier value is not an identifier: " .. st[idx].value)
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


function ScopedIdentifier:new(st, idx)
    local value, new_idx = self.parse(st, idx)
    local new_class = Identifier:protected_new(value)
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
    assert(#self.value == 1, "ScopedIdentifier has multiple values without a '.' PERIOD")
    return false
end


function ScopedIdentifier:getValue(portion_idx)
    local values = self.value

    if not portion_idx then
        -- behave like Identifier
        assert(not self:isScoped(), "getValue() called without index on ScopedIdentifier")
        return values[#values].value
    end

    -- give back requested portion
    local idx = (portion_idx * 2) - 1
    if self:isGlobalScope() then
        if idx == 1 then
            return "<GLOBAL>"
        end
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
    return syntax:concatTokenValues(self.value)
end
