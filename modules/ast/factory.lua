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

local Syntax = require "syntax"


local AstFactory = {}


-- we're going to "register" statement classes in this table, so we can
-- dispatch their constructors easily when building the AST
AstFactory.dispatch_statement_tbl = {}
AstFactory.dispatch_body_tbl = {}


-- registers classes in classname index, and their ttype in dispatch_ttype_tbl
-- if the ttype is a ptype, then register that instead
function AstFactory:registerClass(ttype, classname, class, inBody)
    dassert(ttype, "No ttype given for classname:", classname)

    if ttype then
        dassert(Syntax:isTokenTtype(ttype) or Syntax:isTokenPtype(ttype),
                "Programming error: ttype is neither ttype nor ptype:", ttype)

        dassert(not self.dispatch_statement_tbl[ttype],
                "Programming error: Class ttype", ttype, "already registered for statements")
        self.dispatch_statement_tbl[ttype] = class

        if inBody then
            dassert(not self.dispatch_body_tbl[ttype],
                    "Programming error: Class ttype", ttype, "already registered for bodies")
            self.dispatch_body_tbl[ttype] = class
        end
    end
end


function AstFactory:buildStatement(namespace, statement_table)
    local token = statement_table[1]
    dassert(token and token.ttype, "Statement table missing token or token.ttype")

    local ttype, ptype = token.ttype, token.ptype

    if self.dispatch_statement_tbl[ttype] then
        return self.dispatch_statement_tbl[ttype].new(namespace, statement_table)
    elseif self.dispatch_statement_tbl[ptype] then
        return self.dispatch_statement_tbl[ptype].new(namespace, statement_table)
    else
        derror(token, "\nStatement token type is not supported:", ttype, ", in table:", statement_table)
    end
end


function AstFactory:dispatchBodyStatement(namespace, statement_table)
    local token = statement_table[1]
    dassert(token and token.ttype, "Statement table missing token or token.ttype:", statement_table)

    local ttype, ptype = token.ttype, token.ptype

    if self.dispatch_body_tbl[ttype] then
        return self.dispatch_body_tbl[ttype].new(namespace, statement_table)
    elseif self.dispatch_body_tbl[ptype] then
        return self.dispatch_body_tbl[ptype].new(namespace, statement_table)
    else
        if token:canBeIdentifier() then
            derror(token, "\nStatement type word '", token.value, "' is not supported inside message/group bodies")
        else
            derror(token, "\nThe token type is not supported inside message/group bodies:", ttype,
                  "\n\nThe statement token table:", statement_table)
        end
    end
end


--------------------------------------------------------------------------------
-- helper functions

-- gets the rest of the values from the given subtable, starting at the given
-- index position or 1 if not given; converts everything to a string
function AstFactory.serializeRemaining(st, idx)
    idx = idx or 1
    dassert(#st >= idx, "Programming error: invalid subtable or index")

    local value = ""

    while idx <= #st do
        value = value .. st[idx].value
        idx = idx + 1
    end

    return value
end


-- given a statement table array and one or more ttypes, verify
-- the tokens in the array match the given ttypes, in order
-- a ttype of boolean false is skipped in the array
function AstFactory.verifyTokenTTypes(name, st, ...)
    local ttypes = { ... }

    if #ttypes > #st then
        return false, name .. " statement is missing tokens: need " ..
                        tostring(#ttypes) .. " tokens, but got " .. tostring(#st)
    end

    for idx, ttype in ipairs(ttypes) do
        if ttype then
            if ttype == "IDENTIFIER" then
                -- for identifiers, we verify it could be one
                if not st[idx]:canBeIdentifier() then
                    return false, st[idx], name .. " statement expected an identifer for token #" ..
                                    tostring(idx) .. " but got value '" ..
                                    tostring(st[idx].value) .. "' of type " .. st[idx].ttype
                end
            elseif ttype == "NUMBER" then
                if st[idx].ptype ~= "NUMBER" then
                    return false, st[idx], name .. " statement expected a number for token #" ..
                                    tostring(idx) .. " but got value '" ..
                                    tostring(st[idx].value) .. "' of type " .. st[idx].ttype
                end
            elseif st[idx].ttype ~= ttype then
                return false, st[idx], name .. " statement token #" .. tostring(idx) ..
                                " was expected to be of type " .. ttype ..
                                " but was of type " .. st[idx].ttype ..
                                " with value '" .. tostring(st[idx].value) .. "'"
            end
        end
    end
    return true
end


return AstFactory
