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

local Syntax   = require "syntax"


--------------------------------------------------------------------------------
-- The Token class for the lexer to create and the parser to analyze
--
local Token = {}
local Token_mt = { __index = Token }


function Token.new(ttype, value, cursor)
    local token = Syntax:getTokenForTtype(ttype)
    dassert(token, cursor, "Could not find token for ttype=", ttype)

    local new_class = { -- the new instance
        ["ttype"]    = token.ttype,
        ["ptype"]    = token.ptype,
        ["category"] = token.category,
        ["value"]    = value,
        ["cursor"]   = cursor:clone()
    }
    setmetatable( new_class, Token_mt )
    return new_class
end


function Token:getType()
    return "TOKEN"
end


function Token:getTtype()
    return self.ttype
end


function Token:setTtype(ttype)
    dassert(Syntax:isTokenTtype(ttype), "Programming error: cannot convert token from", self.ttype, "to", ttype)
    self.ttype = ttype
end


function Token:getPtype()
    return self.category
end


function Token:getValue()
    return self.value
end


function Token:getDebugOutput()
    return self.cursor:getDebugOutput() ..
           " token type='" .. string.lower(self.ttype) ..
           "', value='" .. tostring(self.value) .. "'"
end


function Token:canBeIdentifier()
    return (
            self.ttype == "IDENTIFIER" or
            self.category == "WORD" or
            self.ttype == "BOOLEAN_LITERAL"
           )
end


function Token:isNativeType()
    return self.ptype == "NATIVE"
end


local hex_rgx = GRegex.new("^0[xX]([a-fA-F0-9]+)$")
local oct_rgx = GRegex.new("^0([0-7]+)$")


function Token:convertToNumber()
    dassert(self.ptype == "NUMBER", self.cursor, "Token type is not a number type", self.ttype)

    local ttype = self.ttype

    local value
    if ttype == "INTEGER_LITERAL" then
        value = tonumber(self.value)
    elseif ttype == "FLOAT_LITERAL" then
        value = tonumber(self.value)
    elseif ttype == "HEX_LITERAL" then
        local val = hex_rgx:match(self.value)
        dassert(val, self.cursor, "Could not convert hex='", self.value,
                     "' to a number")
        value = tonumber(val, 16)
    elseif ttype == "OCTAL_LITERAL" then
        local val = oct_rgx:match(self.value)
        dassert(val, self.cursor, "Could not convert octal='", self.value,
                     "'' to a number")
        value = tonumber(val, 8)
    end

    dassert(value, self.cursor, "Could not convert '", self.value,
                   "'' to a number")

    return value
end


return Token
