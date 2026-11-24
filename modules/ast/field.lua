----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
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

-- proto3 fields may omit the "optional"/"required"/"repeated" label
-- entirely (they're implicitly "optional" singular fields unless declared
-- "repeated"); such a field statement starts directly with its type, which
-- is either a NATIVE keyword (e.g. "string", "uint32") or a message/enum
-- type IDENTIFIER (e.g. "SessionData" or "ip.Tuple")
AstFactory:registerClass("NATIVE", "FieldStatement", FieldStatement, true)
AstFactory:registerClass("IDENTIFIER", "FieldStatement", FieldStatement, true)

local function trim(value)
    return (value:gsub("^%s+", ""):gsub("%s+$", ""))
end


local function parseDocumentation(comments)
    local documentation = {}
    local in_description = false

    for _, comment in ipairs(comments or {}) do
        for line in comment:gmatch("[^\r\n]+") do
            line = trim(line)
            line = line:gsub("^[/*]+", "")
            line = trim(line)

            local tag, value = line:match("^@([%w_]+)%s*(.*)$")
            if tag == "name" then
                documentation.name = value
                in_description = false
            elseif tag == "desc" then
                documentation.description = value
                in_description = true
            elseif in_description and line ~= "" then
                documentation.description =
                    documentation.description .. "\n" .. line
            end
        end
    end

    return documentation
end


function FieldStatement.parse(st, oneof_name)
    local idx, id, value
    local default_token

    if oneof_name then
        dassert(#st >= 4, "Field statement inside ONEOF is malformed: not 4 or more tokens")
        idx = 1
    elseif st[1].ptype == "LABEL" then
        dassert(#st >= 5, "LABEL field statement is malformed: not 5 or more tokens")
        idx = 2
    else
        -- proto3 implicit (label-less) singular field
        dassert(#st >= 4, "Field statement is malformed: not 4 or more tokens")
        idx = 1
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

    -- see if there's an option, such as "[packed=true]"; the decoder
    -- auto-detects packed-vs-unpacked encoding from the actual wiretype
    -- seen on the wire (see back_end.native), so there's nothing further
    -- to do here other than skip over the bracketed options
    if idx < #st then
        idx = idx + 1
        dassert(st[idx].ttype == "BRACKET_BLOCK", "Field statement has unexpected token after the number: ", st[idx].ttype)
        local options = st[idx].value
        for option_idx, option_token in ipairs(options) do
            if option_token.ttype == "DEFAULT" then
                dassert(options[option_idx + 1] and options[option_idx + 1].ttype == "EQUAL",
                    option_token, "Field default option needs '='")
                default_token = options[option_idx + 2]
                dassert(default_token and default_token.ttype ~= "COMMA",
                    option_token, "Field default option needs a value")
                if default_token.value == "-" then
                    local number_token = options[option_idx + 3]
                    dassert(number_token, option_token, "Field default is missing a number")
                    default_token = {negative = true, token = number_token}
                else
                    default_token = {token = default_token}
                end
            end
        end
    end

    return id, value, tag, default_token
end


local function decodeStringDefault(value)
    value = value:gsub("\\x(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    value = value:gsub("\\([0-7][0-7]?[0-7]?)", function(octal)
        return string.char(tonumber(octal, 8))
    end)
    local escapes = {
        ["n"] = "\n", ["r"] = "\r", ["t"] = "\t", ["b"] = "\b",
        ["f"] = "\f", ["\\"] = "\\", ['"'] = '"', ["'"] = "'",
    }
    return value:gsub("\\(.)", function(character)
        return escapes[character] or character
    end)
end


function FieldStatement:decodeDefault()
    local token = self.default_token.token
    local field_type = self.value:getType()
    if field_type == "STRING" or field_type == "BYTES" then
        dassert(token.ttype == "DOUBLE_QUOTED_STRING" or
                token.ttype == "SINGLE_QUOTED_STRING",
            token, "String/bytes default must be quoted")
        local value = decodeStringDefault(token.value)
        if field_type == "BYTES" then
            local hex = {}
            for index = 1, #value do
                hex[#hex + 1] = string.format("%02x", value:byte(index))
            end
            return ByteArray.new(table.concat(hex))
        end
        return value
    elseif field_type == "BOOL" then
        dassert(token.ttype == "BOOLEAN_LITERAL", token, "Boolean default must be true or false")
        return token.value == "true"
    elseif field_type == "ENUM" then
        dassert(token:canBeIdentifier(), token, "Enum default must name an enumerator")
        for _, enumerator in ipairs(self.value:getValue()) do
            if enumerator:getName() == token.value then
                return enumerator:getValue()
            end
        end
        dassert(false, token, "Unknown enum default '", token.value, "'")
    else
        dassert(token.ptype == "NUMBER", token, "Numeric default must be a number")
        local value = token:convertToNumber()
        return self.default_token.negative and -value or value
    end
end


function FieldStatement.new(namespace, st, oneof_name)
    if st[2] and st[2].ttype == "GROUP" then
        return GroupStatement.new(namespace, st)
    end

    local id, value, tag, default_token = FieldStatement.parse(st, oneof_name)
    local new_class = StatementBase.new("FIELD", id, namespace, value)
    if oneof_name then
        -- this Field occurs in a oneof statement
        new_class["label"] = "ONEOF"
        new_class["oneof_name"] = oneof_name
    elseif st[1].ptype == "LABEL" then
        new_class["label"] = st[1].ttype
    else
        -- proto3 implicit field: singular, i.e. like an "optional" field
        new_class["label"] = "OPTIONAL"
    end
    new_class["tag"] = tag
    new_class["default_token"] = default_token
    new_class["documentation"] = parseDocumentation(st.leading_comments)
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
    if self.default_token then
        dassert(self.label == "OPTIONAL",
            "Default values are only valid on optional singular fields: ", self:getName())
        self.default_value = self:decodeDefault()
    end
end


--------------------------------------------------------------------------------
-- functions for the back_end


function FieldStatement:getDecoder()
    if not self.decoder then
        self.decoder = self.value:getDecoder(self:getProtoField(), self:getTag(),
                                             self:getName(), self.label, self.oneof_name)
        self.decoder.default_value = self.default_value
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

        local documentation = self.documentation or {}
        self.pfield = ProtoField.new(
            documentation.name or name,
            abbrev,
            ftype,
            valstring,
            nil,
            nil,
            documentation.description
        )
    end
    return self.pfield
end


return FieldStatement
