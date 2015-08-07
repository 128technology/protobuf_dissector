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

local AstFactory    = require "ast.factory"
local StatementBase = require "ast.statement_base"


--------------------------------------------------------------------------------
-- The SyntaxStatement statement class
--
-- Although this is derived from StatementBase, it's not used in the AST;
-- it exists for the front-end to use when determining namespaces and joining
-- the separate file parse trees into one
--
local SyntaxStatement = {}
local SyntaxStatement_mt = { __index = SyntaxStatement }
setmetatable( SyntaxStatement, { __index = StatementBase } ) -- inherit from StatementBase
AstFactory:registerClass("SYNTAX", "SyntaxStatement", SyntaxStatement)


function SyntaxStatement.parse(st)
    dassert(AstFactory.verifyTokenTTypes("SYNTAX", st, "SYNTAX", "EQUAL", false))

    local value

    if st[3].ttype == "DOUBLE_QUOTED_STRING" or st[3].ttype == "SINGLE_QUOTED_STRING" then
        value = st[3].value
    else
        value = "proto2"
    end

    return value
end


function SyntaxStatement.new(namespace, st)
    local value = SyntaxStatement.parse(st)
    local new_class = StatementBase.new("SYNTAX", nil, namespace, value) -- the new instance
    setmetatable( new_class, SyntaxStatement_mt )
    return new_class
end


function SyntaxStatement:display()
    return ""
end


function SyntaxStatement:analyze()
    if self.value ~= "proto2" then
        derror("This decoder only supports 'proto2' syntax: ", self.value)
    end
end


return SyntaxStatement
