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

require "ast.base"

local ast = _G["ast"]

local syntax = require "syntax"


--------------------------------------------------------------------------------
-- NativeField class
--
-- This handles all "native" types for the FieldStatement, such as "DOUBLE",
-- "INT64", etc.
--
local NativeField = {}
local NativeField_mt = { __index = NativeField }
setmetatable( NativeField, { __index = ast.Base } ) -- inherit from Base


function NativeField.new(ttype)
    local new_class = ast.Base:new(ttype) -- the new instance
    setmetatable( new_class, NativeField_mt )
    return new_class
end


function NativeField.isNativeType(ttype)
    return syntax:isNativeTtype(ttype)
end


return NativeField
