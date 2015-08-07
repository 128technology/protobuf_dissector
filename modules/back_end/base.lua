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

local back_end = _G["back_end"]
assert(type(back_end) == 'table', "Programming error: no global 'back_end' table")


--------------------------------------------------------------------------------
-- The Base base class, from which others derive
--
-- All Bases have a type
--
local Base = {}
local Base_mt = { __index = Base }
--back_end.registerClass(nil, "Base", Base)


function Base.new(ttype)
    local new_class = {  -- the new instance
        ["ttype"] = ttype,
    }
    setmetatable( new_class, Base_mt )
    return new_class
end


function Base:getType()
    return self.ttype
end
