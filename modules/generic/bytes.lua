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
-- BytesDecoder class, for unknown bytes in LENGTH_DELIMITED fields
--
local BytesDecoder = {}
local BytesDecoder_mt = { __index = BytesDecoder }
setmetatable( BytesDecoder, { __index = Base } ) -- make it inherit from Base



function BytesDecoder.new(pfield)
    local new_class = Base.new("LENGTH_DELIMITED", pfield)
    setmetatable( new_class, BytesDecoder_mt )
    return new_class
end


function BytesDecoder:decode(decoder, tag)
    print("BytesDecoder:decode() called")
    return decoder:addFieldBytes(self.pfield)
end


return BytesDecoder
