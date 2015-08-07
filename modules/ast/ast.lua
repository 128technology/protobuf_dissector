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

--[[
    This script is a Lua module (not stand-alone) for proto file syntax.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

    How it works:

    This module provides functions to build an Abstrat Syntax Tree (AST),
    which in our case is an array of Lua class objects for each protobuf
    statement type. For example there's a "GroupStatement" object to
    represent the "group" statement, and a "MessageStatement" that represents
    the "message" statement, etc.

    Each statement object contains its attributes and an array of zero or more
    statement objects, which represent more statements in its block if it has
    a block. For example the MessageStatement typically has an array of
    multiple statement objects for its fields, whereas a FieldStatement does
    not.

    The AST actually has to be "processed" in multiple phases/times:
        1. The first phase, called the "build" phase, builds an AST for each
           input Parse Tree table of each Proto file. This initial AST does
           not resolve declarations of types. For example, if the proto file
           declares an enum type and even uses that enum type, the AST will
           contain the EnumStatement and its contained EnumeratorStatements,
           and separately contain the FieldStatement that uses that enum, but
           the AST won't resolve the linkage between the two yet. Each proto
           file's tokens array will build one AST in this phase, but all of
           them will be in a single table key'ed by filename.
        3. The third phase, called the "join" phase, looks for package
           statements and puts the separate ASTs into one AST key'ed by
           package scope name; i.e., it creates a namespace model, since
           that's what a protobuf "package really is".
        4. The fourth phase, called the "resolve" phase, determines the linkage
           between declarations and usages. So in the previous example of an
           enum statement, this phase actually links the field using the enum
           to the enum it is using. (likewise messages, map types, etc.)

    After those four phases occur, the AST is complete. Note that this just
    means it's an AST of syntax. Another step is needed to "compile" this into
    a set of usable Dissectors. But that's not done in this module.


]]----------------------------------------

-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end

local inspect = require "inspect"

--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local M = {}

-- we need to load our class modules, and they need access to this module
-- so put our module in global as "ast", so the moduels can find it
if not _G["ast"] then
    _G["ast"] = M
elseif type(_G["ast"]) ~= "table" then
    error("Module ast cannot load because something already exists in _G['ast']")
else
    M = _G["ast"]
end

local syntax = require "syntax"


--------------------------------------------------------------------------------
-- helper functions


-- we're going to "register" statement classes in this table, so we can
-- dispatch their constructors easily when building the AST
M.dispatch_statement_tbl = {}
M.dispatch_body_tbl = {}


-- registers classes in classname index, and their ttype in dispatch_ttype_tbl
-- if the ttype is a ptype, then register that instead
function M:registerClass(ttype, classname, class, inBody)
    assert(not self[classname], "Class " .. classname .. " already registered")
    self[classname] = class

    if ttype then
        assert(syntax:isTokenTtype(ttype) or syntax:isTokenPtype(ttype), "ttype is neither ttype nor ptype: " .. ttype)
        assert(not self.dispatch_statement_tbl[ttype], "Class ttype " .. ttype .. " already registered for statements")
        self.dispatch_statement_tbl[ttype] = class

        if inBody then
            assert(not self.dispatch_body_tbl[ttype], "Class ttype " .. ttype .. " already registered for bodies")
            self.dispatch_body_tbl[ttype] = class
        end
    end
end


function M:buildStatement(namespace, statement_table)
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


function M:dispatchBodyStatement(namespace, statement_table)
    local token = statement_table[1]
    assert(token and token.ttype, "Statement table missing token or token.ttype")
    local ttype, ptype = token.ttype, token.ptype

    if self.dispatch_body_tbl[ttype] then
        return self.dispatch_body_tbl[ttype].new(namespace, statement_table)
    elseif self.dispatch_body_tbl[ptype] then
        return self.dispatch_body_tbl[ptype].new(namespace, statement_table)
    else
        error("Statement token type is not supported on message/group bodies: " .. ttype)
    end
end


-- gets the rest of the values from the given subtable, starting at the given
-- index position or 1 if not given; converts everything to a string
function M.serializeRemaining(st, idx)
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
function M.verifyTokenTTypes(name, st, ...)
    local ttypes = { ... }

    if #ttypes > #st then
        return false, name .. " statement is missing tokens: need " ..
                        tostring(#ttypes) .. " tokens, but got " .. tostring(#st)
    end

    for idx, ttype in ipairs(ttypes) do
        if ttype then
            if ttype == "IDENTIFIER" then
                -- for identifiers, we verify it could be one
                if not syntax:canTokenBeIdentifier(st[idx]) then
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




----------------------------------------
--
--  Class definitions section
--
----------------------------------------

----------------------------------------
-- now require our classes
local Namespace = require "ast.namespace"
--require "ast.identifier"
local Package = require "ast.package"
require "ast.option"
require "ast.enum"
require "ast.field"
require "ast.message"

print("AST modules loaded")


--------------------------------------------------------------------------------
-- more private functions

function M:getPackage(parse_tree)
    for _, statement in ipairs(parse_tree) do
        if statement[1].ttype == "PACKAGE" then
            return Package.new(statement)
        end
    end
end


function M:buildAsts(proto_files)
    local global_ns = Namespace.new()

    for _, filetbl in pairs(proto_files) do
        local parse_tree = filetbl.parse_tree
        local ns = global_ns

        local pkg = self:getPackage(parse_tree)

        if pkg then
            -- find or generate the namespace
            ns = global_ns:findOrCreateAbsolute(pkg:getId())
        end

        ns:buildAst(parse_tree)
    end

    return global_ns
end




--------------------------------------------------------------------------------

function M:reset()
    self.ast = {}
end


function M:init()
end


-- builds the ASTs for the given combo global_namespace_tree
function M:build(proto_files)

    local global_namespace = self:buildAsts(proto_files)
    print("AST built")

    global_namespace:analyze()
    print("AST analyzed")

    return global_namespace
end


return M
