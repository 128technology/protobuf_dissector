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

local Base   = require "ast.base"
local Syntax = require "syntax"


local decoder_class = {
    ["DOUBLE"]    = require "back_end.double",
    ["FLOAT"]     = require "back_end.float",
    ["FIXED32"]   = require "back_end.fixed32",
    ["FIXED64"]   = require "back_end.fixed64",
    ["SFIXED32"]  = require "back_end.sfixed32",
    ["SFIXED64"]  = require "back_end.sfixed64",
    ["INT32"]     = require "back_end.int32",
    ["INT64"]     = require "back_end.int64",
    ["UINT32"]    = require "back_end.uint32",
    ["UINT64"]    = require "back_end.uint64",
    ["STRING"]    = require "back_end.string",
    ["BOOL"]      = require "back_end.bool",
    ["BYTES"]     = require "back_end.bytes",
}


--------------------------------------------------------------------------------
-- NativeField class
--
-- This handles all "native" types for the FieldStatement, such as "DOUBLE",
-- "INT64", etc.
--
local NativeField = {}
local NativeField_mt = { __index = NativeField }
setmetatable( NativeField, { __index = Base } ) -- inherit from Base


function NativeField.new(ttype)
    local new_class = Base.new(ttype) -- the new instance
    setmetatable( new_class, NativeField_mt )
    return new_class
end


function NativeField.isNativeType(ttype)
    return Syntax:isNativeTtype(ttype)
end


function NativeField:getDecoder(pfield, tag, name, label, oneof_name)
    assert(decoder_class[self:getType()], "Programming error: no native decoder for: " .. self:getType())
    return decoder_class[self:getType()].new(pfield, tag, name, label, oneof_name)
end


return NativeField
