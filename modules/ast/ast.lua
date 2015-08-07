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
    This script is a Lua module (not stand-alone) for proto file Syntax.

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
        2. The second phase, called the "join" phase, looks for package
           statements and puts the separate ASTs into one AST key'ed by
           package scope name; i.e., it creates a namespace model, since
           that's what a protobuf "package" really is.
        3. The third phase, called the "resolve" phase, determines the linkage
           between declarations and usages. So in the previous example of an
           enum statement, this phase actually links the field using the enum
           to the enum it is using. (likewise messages, map types, etc.)

    After those four phases occur, the AST is complete. Note that this just
    means it's an AST of Syntax. Another step is needed to "compile" this into
    a set of usable Dissectors. But that's not done in this module.


]]----------------------------------------

-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror


local Syntax  = require "syntax"

--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local Ast = {}


----------------------------------------
-- now require our classes
local Namespace = require "ast.namespace"
--require "ast.identifier"
local PackageStatement = require "ast.package"
require "ast.option"
require "ast.enum"
require "ast.field"
require "ast.message"
require "ast.oneof"
require "ast.ignore"
require "ast.syntax"

print("AST modules loaded")


--------------------------------------------------------------------------------
-- more private functions

function Ast:getPackage(parse_tree)
    for _, statement in ipairs(parse_tree) do
        if statement[1].ttype == "PACKAGE" then
            return PackageStatement.new(statement)
        end
    end
end


function Ast:buildAsts(proto_files)
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

function Ast:reset()
    self.ast = {}
end


function Ast:init()
end


-- builds the ASTs for the given combo global_namespace_tree
function Ast:build(proto_files)

    local global_namespace = self:buildAsts(proto_files)
    dprint("AST built")

    global_namespace:analyze()
    dprint("AST analyzed")

    return global_namespace
end


return Ast
