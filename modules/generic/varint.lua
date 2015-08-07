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
-- VarintDecoder class, for "fixed64" fields
--
local VarintDecoder = {}
local VarintDecoder_mt = { __index = VarintDecoder }
setmetatable( VarintDecoder, { __index = Base } ) -- make it inherit from Base



function VarintDecoder.new(pfield)
    local new_class = Base.new("VARINT", pfield)
    setmetatable( new_class, VarintDecoder_mt )
    return new_class
end


function VarintDecoder:decode(decoder, tag)
    print("VarintDecoder:decode() called")
    return decoder:addFieldVarint64(self.pfield)
end


return VarintDecoder
