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

--[[
    This script is a Lua module (not stand-alone) for parsing proto files.

    The parsing step is rather simple, since it does not include the lexer nor
    building the aST; instead, it just builds a parse tree.

    This module follows the classic Lua module method of storing its public
    methods/functions in a table and passing back the table to the caller of
    this module file.

    How this works:

    The parser is initialized with the Token Info table. When parse() is
    invoked, it builds a Parse Tree, which unlike an Abstract Syntax Tree is
    just a simple representation of the original lex'ed Token List with some
    more structure. The returned Parse Tree is an array of tables - each table
    represents a proto statement. The statement table is an array of tokens
    for that statement. If the statement included a block (a braces {...}),
    then a "BLOCK" token is appended to the statement's array, with a token
    value being an array of more statements. Thus this can be a tree with many
    branches of branches. The "SEMI" tokens are not added, nor are the
    "L_BRACE" or "R_BRACE" tokens.

]]-----------------------------------------------------------------------------

-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end


local inspect = require("inspect")


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
local DEBUG = debug_level.LEVEL_1


----------------------------------------
-- our module table that we return to the caller of this script
local Parser = { debug_level  = DEBUG }

local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if Parser.debug_level > debug_level.DISABLED then
        dprint = function(...)
            local args = { ... }
            local t = {}

            for _, arg in ipairs(args) do
                if type(arg) =="string" then
                    t[#t+1] = arg
                elseif type(arg) == "table" then
                    t[#t+1] = inspect(arg)
                else
                    t[#t+1] = tostring(arg)
                end
            end

            info(table.concat(t," "))
        end

        if Parser.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()




-- this handles tokens inside []/<>/() blocks
-- the {} blocks are handled separately
function Parser:processBlockTokens(parse_tree, token_list, idx, list_size, context, context_end)
    local Syntax = self.Syntax

    while idx <= list_size do
        local token = token_list[idx]

        local ttype = token.ttype

        if Syntax:isCommentToken(token) then
            -- skip comments (for now?)
            idx = idx + 1

        elseif ttype == "SEMI" then
            dprint2(self.root)
            error("Found ';' inside a " .. context .. " block at index ".. tostring(idx))
        elseif ttype == "R_BRACE" then
            dprint2(self.root)
            error("Found '}' inside a " .. context .. " block at index ".. tostring(idx))
        elseif ttype == "L_BRACE" then
            dprint2(self.root)
            error("Found '{' inside a " .. context .. " block at index ".. tostring(idx))

        elseif ttype == context_end then
            -- we're done
            dprint2("processBlockTokens: found context_end=", ttype, "- returning")
            return idx+1

        elseif Syntax:tokenBeginsBlock(token) then
            -- start a new context, recurse
            local btoken = Syntax:createBlockToken(token)
            dprint2("processBlockTokens: Calling processBlockTokens, previous context=", context)
            idx = self:processBlockTokens(btoken.value, token_list, idx+1, list_size, btoken.begin_ttype, btoken.end_ttype)
            parse_tree[#parse_tree + 1] = btoken
            -- keep going

        else
            parse_tree[#parse_tree + 1] = token
            idx = idx + 1
        end
    end
    return idx
end


-- this handles tokens for a statement
function Parser:processStatementTokens(parse_tree, token_list, idx, list_size, context)
    local Syntax = self.Syntax

    while idx <= list_size do
        local token = token_list[idx]

        local ttype = token.ttype

        if Syntax:isCommentToken(token) then
            -- skip comments (for now?)
            idx = idx + 1

        elseif ttype == "SEMI" then
            -- we're done with this statement
            dprint2("processStatementTokens: found SEMI, returning")
            return idx+1

        elseif ttype == "R_BRACE" then
            -- we shouldn't get here; we should have found a SEMI
            dprint2(self.root)
            error("Found '}' without previous matching '{' nor a ';' at index ".. tostring(idx))

        elseif ttype == "L_BRACE" then
            -- start a new context, recurse
            local t = { ttype = "BRACE_BLOCK", value = {} }
            dprint2("processStatementTokens: Calling processHeadTokens, previous context=", context)
            idx = self:processHeadTokens(t.value, token_list, idx+1, list_size, "L_BRACE")
            parse_tree[#parse_tree + 1] = t
            -- we're done with this statement
            return idx

        elseif Syntax:tokenBeginsBlock(token) then
            -- start a new context
            local btoken = Syntax:createBlockToken(token)
            dprint2("processStatementTokens: Calling processBlockTokens, previous context=", context)
            idx = self:processBlockTokens(btoken.value, token_list, idx+1, list_size, btoken.begin_ttype, btoken.end_ttype)
            parse_tree[#parse_tree + 1] = btoken
            -- keep going
            -- idx was incremented by processBlockTokens
        else
            dprint2("Adding token to tree: ", ttype)
            parse_tree[#parse_tree + 1] = token
            idx = idx + 1
        end
    end
    return idx
end


-- this handles lists of statements - i.e., tokens inside {} blocks as well as the root
function Parser:processHeadTokens(parse_tree, token_list, idx, list_size, context)
    -- we need to be able to skip ahead and recurse and so on, so we can't use
    -- an ipairs() for-loop, but have to do it the long way instead
    local Syntax = self.Syntax
    local has_context = context and context == "L_BRACE" or false

    dprint2("processHeadTokens called with context=", context, "has_context=", has_context)

    while idx <= list_size do
        local token = token_list[idx]

        if has_context and token.ttype == "R_BRACE" then
            dprint2("processHeadTokens: Found end of a brace block")
            return idx+1
        end

        if Syntax:isCommentToken(token) then
            -- skip comments (for now?)
            idx = idx + 1
        else
            if not Syntax:isStatementHeadToken(token) then
                dprint2(self.root)
                error("Token ttype " .. token.ttype .. " cannot be a leading statement token, at index ".. tostring(idx))
            end

            local t = {}
            dprint2("processHeadTokens: Calling processStatementTokens, previous context=", context)
            idx = self:processStatementTokens(t, token_list, idx, list_size)
            parse_tree[#parse_tree + 1] = t
            -- idx was already incremented by processStatementTokens()
        end
    end
    return idx
end




--------------------------------------------------------------------------------
--
-- the public functions of the module
--
--------------------------------------------------------------------------------

function Parser:init(Syntax)
    self.Syntax = Syntax
    resetDebugLevel()
end


function Parser:parse(token_list)
    local parse_tree = {}

    -- for debug info within other funcs
    self.root = parse_tree

    local idx = self:processHeadTokens(parse_tree, token_list, 1, #token_list)

    if idx ~= #token_list+1 then
        dprint2(self.root)
        error("Not all tokens in the Token List were processed. Processed up to index " .. tostring(idx))
    end

    self.root = nil

    return parse_tree
end


function Parser:dump(pfunc, parse_tree)
    pfunc(inspect(parse_tree))
end


return Parser
