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


local Base          = require "ast.base"
local Syntax        = require "syntax"
local NativeDecoder = require "back_end.native"


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


function NativeField:getDecoder(pfield, tag, name, label, oneof_name)
    return NativeDecoder.new(self:getType(), pfield, tag, name, label, oneof_name)
end


return NativeField
