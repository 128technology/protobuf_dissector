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

local AstFactory       = require "ast.factory"
local StatementBase    = require "ast.statement_base"
local Identifier       = require "ast.identifier"
local NativeField      = require "ast.native"
local ScopedIdentifier = require "ast.scoped_identifier"
local GroupStatement   = require "ast.group"


--------------------------------------------------------------------------------
-- FieldStatement class, for labeled field statements
--
--[[

    Handles things like this:
        optional foo.bar nested_message = 2;
        repeated int32 samples = 4 [packed=true];

    The FieldStatement's 'value' is another object (possibly created after
    analyze() is invoked) that represents the native/underlying type of the
    Field. For example a Field for a Message will have a 'value' of the MessageStatement
    object it represents, after analyze() is invoked to resolve the ScopedIdentifier.

    The FieldStatement's 'id' is the name Identifier of the Field; the 'tag'
    is the tag number; the 'label' is the label type.

    During the compiler's back-end processing, createProtoField() will be
    invoked to create a wireshark ProtoField object for each FieldStatement.
    The created ProtoField will be stored in this FieldStatement object rather
    than the underlying 'value' object, since the same Message/Enum can be
    used multiple times as different fields/tags. This ProtoField will be
    displayed in the dissection tree, for its underlying ftype (i.e.,
    ftype.DOUBLE, etc.) and decoded value, and the Decoder will also add a
    sub-tree node for the generic protobuf tag, wiretype, and value fields
    that comprise the field on the wire. For fields of Message types, however,
    it will add this ProtoField and the sub-tree nodes for generic protobuf
    info, but also a sub-tree node of the Proto for the Message, and that sub-
    tree node will then contain a sub-tree of its own fields, and so on.

]]--
local FieldStatement = {}
local FieldStatement_mt = { __index = FieldStatement }
setmetatable( FieldStatement, { __index = StatementBase } ) -- make it inherit from StatementBase
AstFactory:registerClass("LABEL", "FieldStatement", FieldStatement, true)


function FieldStatement.parse(st, oneof_name)
    local idx, id, value

    if oneof_name then
        dassert(#st >= 4, "Field statement inside ONEOF is malformed: not 4 or more tokens")
        idx = 1
    else
        dassert(st[1].ptype == "LABEL", "Token ptype is not LABEL")
        dassert(#st >= 5, "LABEL field statement is malformed: not 5 or more tokens")
        idx = 2
    end

    if st[idx]:isNativeType() then
        value = NativeField.new(st[idx].ttype)
        idx = idx + 1
    else
        -- we wont' know the native type until the AST is analyzed
        value, idx = ScopedIdentifier.new(st, idx)
    end

    local id
    id, idx = Identifier.new(st, idx)

    dassert(st[idx].ttype == "EQUAL", "Field statement argument #", idx, " is not an '=' symbol")
    idx = idx + 1

    dassert(st[idx].ptype == "NUMBER", "Field statement argument #", idx, " is not a number")
    local tag = st[idx]:convertToNumber()

    -- see if there's an option, so we can check for "packed"
    if idx < #st then
        idx = idx + 1
        dassert(st[idx].ttype == "BRACKET_BLOCK", "Field statement has unexpected token after the number: ", st[idx].ttype)
        local t = st[idx].value
        if type(t) == 'table' and #t >= 3 and t[1].ptype == "STRING" and t[1].value == "packed" then
            dassert(t[3].value ~= "true", "Packed encoding format not yet supported")
        end
    end

    return id, value, tag
end


function FieldStatement.new(namespace, st, oneof_name)
    if st[2] and st[2].ttype == "GROUP" then
        return GroupStatement.new(namespace, st)
    end

    local id, value, tag = FieldStatement.parse(st, oneof_name)
    local new_class = StatementBase.new("FIELD", id, namespace, value)
    if oneof_name then
        -- this Field occurs in a oneof statement
        new_class["label"] = "ONEOF"
        new_class["oneof_name"] = oneof_name
    else
        new_class["label"] = st[1].ttype
    end
    new_class["tag"] = tag
    setmetatable( new_class, FieldStatement_mt )
    return new_class
end


function FieldStatement:getTag()
    return self.tag
end


function FieldStatement:analyze()
    if self.value:getType() == "IDENTIFIER" then
        local value = self.value:resolve(self.namespace)
        dassert(value, "Could not resolve scoped identifier '", self.value:display(), "'")
        self.value = value
    end
end


--------------------------------------------------------------------------------
-- functions for the back_end


function FieldStatement:getDecoder()
    if not self.decoder then
        self.decoder = self.value:getDecoder(self:getProtoField(), self:getTag(),
                                             self:getName(), self.label, self.oneof_name)
    end
    return self.decoder
end


function FieldStatement:getProtoField()
    if not self.pfield then
        local name = self:getName()
        local abbrev = string.lower(self.namespace:getFullName() .. "." .. name)
        local ftype = self.value:getFieldType()

        local valstring = nil
        if self.value:getType() == "ENUM" then
            valstring = self.value:getValueString()
        end

        self.pfield = ProtoField.new(name, abbrev, ftype, valstring)
    end
    return self.pfield
end


return FieldStatement
