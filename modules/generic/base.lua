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


--------------------------------------------------------------------------------
-- The Base base class, from which others derive
--
-- All Bases have a type
--
local Base = {}
local Base_mt = { __index = Base }


function Base.new(ttype, pfield)
    local new_class = {  -- the new instance
        ["ttype"] = ttype,
        ["pfield"] = pfield,
    }
    setmetatable( new_class, Base_mt )
    return new_class
end


function Base:getType()
    return self.ttype
end


function Base:getPfield()
    return self.pfield
end


return Base
