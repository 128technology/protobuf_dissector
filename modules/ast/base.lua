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

local ast = _G["ast"]
assert(type(ast) == 'table', "Programming error: no global 'ast' table")
local syntax = _G["syntax"]


--------------------------------------------------------------------------------
-- The Base base class, from which others derive
--
-- All Bases have a type
--
local Base = {}
local Base_mt = { __index = Base }
ast:registerClass(nil, "Base", Base)

function Base:new(ttype)
    local new_class = {  -- the new instance
        ["ttype"] = ttype,
    }
    setmetatable( new_class, Base_mt )
    return new_class
end


function Base:getType()
    return self.ttype
end


function Base:getFieldType()
    return syntax:getFtypeForTtype(self.ttype)
end
