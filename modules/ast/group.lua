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

local AstFactory       = require "ast.ast_factory"
local StatementBase    = require "ast.statement_base"
local Identifier       = require "ast.identifier"


----------------------------------------
-- GroupStatement class
--
local GroupStatement = {}
local GroupStatement_mt = { __index = GroupStatement } 
setmetatable( GroupStatement, { __index = StatementBase } ) -- make it inherit from StatementBase


function GroupStatement.parse(st, namespace)
    assert(st[1].ptype == "LABEL", "Token ptype is not LABEL")
    assert(#st >= 6, "LABEL group statement is malformed: not 6 or more tokens")

    assert(AstFactory.verifyTokenTTypes("GROUP", st, false, "START_GROUP", "IDENTIFIER", "EQUAL", "NUMBER", "BRACE_BLOCK"))

    local value  = {}
    for _,tokens in ipairs(st[6].value) do
        value[#value+1] = AstFactory:dispatchBodyStatement(namespace, tokens)
    end

    return Identifier.new(st, 3), value, tonumber(st[5].value)
end


function GroupStatement.new(namespace, st)
    local id, tag = GroupStatement.parse(st, namespace)
    local new_class = StatementBase.new("START_GROUP", id, namespace, value)
    new_class["tag"] = tag
    new_class["label"] = st[1].ttype
    setmetatable( new_class, GroupStatement_mt )
    return new_class
end


function GroupStatement:getTag()
    return self.tag
end


local ignore_types = {
    OPTION = true,
    -- the ONEOF will add its fields to the Message before being ignored
    ONEOF = true,
    -- remove these, so they end up only being in their namespace's
    -- declaration tables
    MESSAGE = true,
    ENUM = true,
}

function GroupStatement:analyze()
    local fields = {}
    -- temporary tags table to verify no duplicate tags
    local tags = {}
    for _, object in ipairs(self.value) do
        object:analyze(fields, tags)
        if not ignore_types[object:getType()] then
            assert(not tags[object:getTag()], "Two fields with same tag number in Group")
            tags[object:getTag()] = object
            fields[#fields+1] = object
        end
    end
    self.value = fields
end




--------------------------------------------------------------------------------
-- functions for the back_end

local GroupDecoder   = require "back_end.group"


function GroupStatement:createTagTable()
    if not self.tag_table then
        local tags = {}
        for _, field in ipairs(self.value) do
            local pfield = field:getProtoField()
            tags[field:getTag()] = field:getDecoder(pfield, field:getTag(), field:getName())
        end
        self.tag_table = tags
    end
    return self.tag_table
end


function GroupStatement:getPFields(pfields)
    for _, field in ipairs(self.value) do
        local pfield = field:getProtoField(pfields)
        pfields[#pfields+1] = pfield
    end
end


function GroupStatement:getDecoder()
    if not self.decoder then
        self:createTagTable()
        self.decoder = GroupDecoder.new(self:getProtoField(), self:getTag(), self:getName(), self.tag_table)
    end
    return self.decoder
end


function GroupStatement:getProtoField(pfields)
    if pfields then
        self:getPFields(pfields)
    end

    if not self.pfield then
        local name = self:getName()
        local abbrev = string.lower(self.namespace:getFullName() .. "." .. name)
        local ftype = self:getFieldType()

        self.pfield = ProtoField.new(name, abbrev, ftype)
    end
    return self.pfield
end


return GroupStatement
