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
-- Fixed64Decoder class, for "fixed64" fields
--
local Fixed64Decoder = {}
local Fixed64Decoder_mt = { __index = Fixed64Decoder }
setmetatable( Fixed64Decoder, { __index = Base } ) -- make it inherit from Base


function Fixed64Decoder.new(pfield, tag, name)
    local new_class = Base.new("FIXED64", pfield, tag, name)
    setmetatable( new_class, Fixed64Decoder_mt )
    return new_class
end


function Fixed64Decoder:decode(decoder)
    return decoder:addFieldStruct(self.pfield, "<E", 8)
end


return Fixed64Decoder
