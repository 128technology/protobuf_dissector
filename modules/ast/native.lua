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

local Base   = require "ast.base"
local syntax = require "syntax"


local decoder_class = {
    ["DOUBLE"] = require "back_end.double",
    ["FLOAT"]  = require "back_end.float",
    ["INT32"]  = require "back_end.int32",
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
    return syntax:isNativeTtype(ttype)
end


function NativeField:getDecoder(pfield, tag, name)
    assert(decoder_class[self:getType()], "Programming error: no native decoder for: " .. self:getType())
    return decoder_class[self:getType()].new(pfield, tag, name)
end


return NativeField
