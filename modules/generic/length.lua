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

local Base = require "generic.base"


----------------------------------------
-- LengthDecoder class, for group fields
--
local LengthDecoder = {}
local LengthDecoder_mt = { __index = LengthDecoder }
setmetatable( LengthDecoder, { __index = Base } ) -- make it inherit from Base



function LengthDecoder.new(pfield)
    local new_class = Base.new("LENGTH_DELIMITED", pfield)
    setmetatable( new_class, LengthDecoder_mt )
    return new_class
end


function LengthDecoder:decode(decoder)
    print("LengthDecoder:decode() called")
    return decoder:addFieldVarint64(self.pfield)
end


return LengthDecoder
