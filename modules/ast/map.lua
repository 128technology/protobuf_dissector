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

local AstFactory      = require "ast.factory"
local Token           = require "front_end.token"
local MessageStatement = require "ast.message"
local FieldStatement   = require "ast.field"


--------------------------------------------------------------------------------
-- MapStatement class, for "map<K,V> name = tag;" field statements
--
--[[

    Protobuf map fields are wire-format sugar: a declaration such as

        map<string, SessionData> sessions = 7;

    is defined (by the protobuf spec) to be identical, on the wire, to:

        message SessionsEntry {
            string      key   = 1;
            SessionData value = 2;
        }
        repeated SessionsEntry sessions = 7;

    So rather than teach the decoder/back_end a whole new field kind, we
    synthesize the equivalent nested "Entry" MessageStatement and "repeated"
    FieldStatement here, at AST-build time, out of synthetic Token objects
    fed through the existing MessageStatement.new()/FieldStatement.new()
    constructors - this reuses all of the existing Proto/ProtoField/decoder
    machinery for free.

    MapStatement itself is just a thin proxy: it behaves like a FIELD (so it
    can live inside a Message's 'value' array next to ordinary fields), but
    delegates everything to the synthesized 'field' (the repeated EntryName
    field), while making sure the synthesized 'entry_message' also gets its
    analyze() invoked (since analyze() is only ever invoked by walking the
    enclosing Message's 'value' array, not the Namespace's decls table).

]]--
local MapStatement = {}
local MapStatement_mt = { __index = MapStatement }
AstFactory:registerClass("MAP", "MapStatement", MapStatement, true)


-- converts a map field's name into the conventional nested "Entry" message
-- name that protoc itself would generate, e.g. "my_field" -> "MyFieldEntry"
local function toEntryName(field_name)
    local name = field_name:gsub("_(%a)", function(c) return string.upper(c) end)
    name = name:gsub("^%a", string.upper)
    return name .. "Entry"
end


function MapStatement.new(namespace, st)
    dassert(AstFactory.verifyTokenTTypes("Map", st, "MAP", "ANGLE_BLOCK", "IDENTIFIER", "EQUAL", "NUMBER"))

    local angle = st[2].value
    dassert(angle and #angle >= 3, "map<K,V> statement is missing key/value types")

    local comma_idx
    for i, token in ipairs(angle) do
        if token.ttype == "COMMA" then
            comma_idx = i
            break
        end
    end
    dassert(comma_idx, "map<K,V> statement is missing a ',' between key and value types")
    dassert(comma_idx == 2, "map key type must be a single native scalar type")

    local key_type_token = angle[1]
    dassert(key_type_token:isNativeType(), "map key type must be a native scalar type, not: '",
            tostring(key_type_token.value), "'")

    local value_type_tokens = {}
    for i = comma_idx+1, #angle do
        value_type_tokens[#value_type_tokens+1] = angle[i]
    end
    dassert(#value_type_tokens >= 1, "map<K,V> statement is missing a value type")

    local field_name_token = st[3]
    local tag_token        = st[5]
    local cursor           = st[1].cursor

    local entry_name = toEntryName(field_name_token.value)

    -- synthesize: message EntryName { KEY_TYPE key = 1; VALUE_TYPE value = 2; }
    local key_field_tokens = {
        key_type_token,
        Token.new("IDENTIFIER", "key", cursor),
        Token.new("EQUAL", "=", cursor),
        Token.new("INTEGER_LITERAL", "1", cursor),
    }

    local value_field_tokens = {}
    for _, token in ipairs(value_type_tokens) do
        value_field_tokens[#value_field_tokens+1] = token
    end
    value_field_tokens[#value_field_tokens+1] = Token.new("IDENTIFIER", "value", cursor)
    value_field_tokens[#value_field_tokens+1] = Token.new("EQUAL", "=", cursor)
    value_field_tokens[#value_field_tokens+1] = Token.new("INTEGER_LITERAL", "2", cursor)

    local entry_st = {
        Token.new("MESSAGE", "message", cursor),
        Token.new("IDENTIFIER", entry_name, cursor),
        { ttype = "BRACE_BLOCK", value = { key_field_tokens, value_field_tokens } },
    }

    -- this registers "entry_name" as a declaration inside 'namespace',
    -- which must happen *before* we build the field referencing it below
    local entry_message = MessageStatement.new(namespace, entry_st)

    -- synthesize: repeated EntryName field_name = tag;
    local field_st = {
        Token.new("REPEATED", "repeated", cursor),
        Token.new("IDENTIFIER", entry_name, cursor),
        field_name_token,
        Token.new("EQUAL", "=", cursor),
        tag_token,
    }

    local field = FieldStatement.new(namespace, field_st)

    local new_class = {
        ["entry_message"] = entry_message,
        ["field"] = field,
    }
    setmetatable( new_class, MapStatement_mt )
    return new_class
end


function MapStatement:getType()
    return "FIELD"
end


function MapStatement:getTag()
    return self.field:getTag()
end


function MapStatement:getName()
    return self.field:getName()
end


-- this is invoked by the enclosing Message's analyze(); we must also
-- analyze() the synthesized entry_message ourselves, since it's not
-- reachable any other way (it lives only in the Namespace's decls table,
-- which is walked for Proto creation but not for analyze())
function MapStatement:analyze(fields, tags)
    self.entry_message:analyze()
    self.field:analyze(fields, tags)
end


function MapStatement:getProtoField(pfields)
    return self.field:getProtoField(pfields)
end


function MapStatement:getDecoder(pfield, tag, name, label, oneof_name)
    return self.field:getDecoder(pfield, tag, name, label, oneof_name)
end


return MapStatement
