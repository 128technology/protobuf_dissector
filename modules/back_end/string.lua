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

local Base = require "back_end.base"


----------------------------------------
-- StringDecoder class, for "string" length-encoded fields
--
local StringDecoder = {}
local StringDecoder_mt = { __index = StringDecoder }
setmetatable( StringDecoder, { __index = Base } ) -- make it inherit from Base


function StringDecoder.new(pfield, tag, name)
    local new_class = Base.new("STRING", pfield, tag, name)
    setmetatable( new_class, StringDecoder_mt )
    return new_class
end


function StringDecoder:decode(decoder)
    return decoder:addFieldString(self.pfield)
end


return StringDecoder
