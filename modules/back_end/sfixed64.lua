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
-- SFixed64Decoder class, for "sfixed64" fields
--
local SFixed64Decoder = {}
local SFixed64Decoder_mt = { __index = SFixed64Decoder }
setmetatable( SFixed64Decoder, { __index = Base } ) -- make it inherit from Base


function SFixed64Decoder.new(pfield, tag, name)
    local new_class = Base.new("SFIXED64", pfield, tag, name)
    setmetatable( new_class, SFixed64Decoder_mt )
    return new_class
end


function SFixed64Decoder:decode(decoder)
    return decoder:addFieldStruct(self.pfield, "<e", 8)
end


return SFixed64Decoder
