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

local AstFactory     = require "ast.factory"
local StatementBase  = require "ast.statement_base"
local FieldStatement = require "ast.field"
local Identifier     = require "ast.identifier"


----------------------------------------
-- OneofStatement class
--
local OneofStatement = {}
local OneofStatement_mt = { __index = OneofStatement }
setmetatable( OneofStatement, { __index = StatementBase } ) -- make it inherit from StatementBase
AstFactory:registerClass("ONEOF", "OneofStatement", OneofStatement, true)


function OneofStatement.parse(st, namespace)
    dassert(AstFactory.verifyTokenTTypes("Oneof", st, "ONEOF", "IDENTIFIER", "BRACE_BLOCK"))

    local id = Identifier.new(st, 2)

    local value  = {}

    for _,tokens in ipairs(st[3].value) do
        value[#value+1] = FieldStatement.new(namespace, tokens, id:display())
    end

    return id, value
end


function OneofStatement.new(namespace, st)
    local id, value = OneofStatement.parse(st, namespace)
    local new_class = StatementBase.new("ONEOF", id, namespace, value)
    setmetatable( new_class, OneofStatement_mt )
    new_class:setValue(value)
    return new_class
end


function OneofStatement:analyze(fields, tags)
    for _, object in ipairs(self.value) do
        object:analyze()
        dassert(not tags[object:getTag()], "Two fields with same tag number in Message/Oneof")
        tags[object:getTag()] = object
        fields[#fields+1] = object
    end
end


return OneofStatement
