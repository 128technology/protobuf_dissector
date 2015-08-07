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
-- SInt64Decoder class, for "sint64" varint fields
--
local SInt64Decoder = {}
local SInt64Decoder_mt = { __index = SInt64Decoder }
setmetatable( SInt64Decoder, { __index = Base } ) -- make it inherit from Base


function SInt64Decoder.new(pfield, tag, name)
    local new_class = Base.new("UINT64", pfield, tag, name)
    setmetatable( new_class, SInt64Decoder_mt )
    return new_class
end


function SInt64Decoder:decode(decoder)
    return decoder:addFieldVarint64(self.pfield)
end


return SInt64Decoder
