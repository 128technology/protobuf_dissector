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

local Syntax = require "syntax"


local AstFactory = {}


-- we're going to "register" statement classes in this table, so we can
-- dispatch their constructors easily when building the AST
AstFactory.dispatch_statement_tbl = {}
AstFactory.dispatch_body_tbl = {}


-- registers classes in classname index, and their ttype in dispatch_ttype_tbl
-- if the ttype is a ptype, then register that instead
function AstFactory:registerClass(ttype, classname, class, inBody)
    assert(ttype, "No ttype given for classname: " .. classname)

    if ttype then
        assert(Syntax:isTokenTtype(ttype) or Syntax:isTokenPtype(ttype), "ttype is neither ttype nor ptype: " .. ttype)
        assert(not self.dispatch_statement_tbl[ttype], "Class ttype " .. ttype .. " already registered for statements")
        self.dispatch_statement_tbl[ttype] = class

        if inBody then
            assert(not self.dispatch_body_tbl[ttype], "Class ttype " .. ttype .. " already registered for bodies")
            self.dispatch_body_tbl[ttype] = class
        end
    end
end


function AstFactory:buildStatement(namespace, statement_table)
    local token = statement_table[1]
    assert(token and token.ttype, "Statement table missing token or token.ttype")
    local ttype, ptype = token.ttype, token.ptype

    if self.dispatch_statement_tbl[ttype] then
        return self.dispatch_statement_tbl[ttype].new(namespace, statement_table)
    elseif self.dispatch_statement_tbl[ptype] then
        return self.dispatch_statement_tbl[ptype].new(namespace, statement_table)
    else
        error("Statement token type is not supported: " .. ttype)
    end
end


function AstFactory:dispatchBodyStatement(namespace, statement_table)
    local token = statement_table[1]
    assert(token and token.ttype, "Statement table missing token or token.ttype")
    local ttype, ptype = token.ttype, token.ptype

    if self.dispatch_body_tbl[ttype] then
        return self.dispatch_body_tbl[ttype].new(namespace, statement_table)
    elseif self.dispatch_body_tbl[ptype] then
        return self.dispatch_body_tbl[ptype].new(namespace, statement_table)
    else
        error("Statement token type is not supported on message/group bodies: " .. ttype ..
              "\nstatement token table=\n" .. inspect(statement_table))
    end
end


--------------------------------------------------------------------------------
-- helper functions

-- gets the rest of the values from the given subtable, starting at the given
-- index position or 1 if not given; converts everything to a string
function AstFactory.serializeRemaining(st, idx)
    idx = idx or 1
    assert(#st >= idx, "serializeRemaining: invalid subtable or index")

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
                if not Syntax:canTokenBeIdentifier(st[idx]) then
                    return false, name .. " statement expected an identifer for token #" ..
                                    tostring(idx) .. " but got value '" ..
                                    tostring(st[idx].value) .. "' of type " .. st[idx].ttype
                end
            elseif st[idx].ttype ~= ttype then
                return false, name .. " statement token #" .. tostring(idx) ..
                                " was expected to be of type " .. ttype ..
                                " but was of type " .. st[idx].ttype ..
                                " with value '" .. tostring(st[idx].value) .. "'"
            end
        end
    end
    return true
end



return AstFactory
