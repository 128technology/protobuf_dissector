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
-- SInt32Decoder class, for "sint32" varint fields
--
local SInt32Decoder = {}
local SInt32Decoder_mt = { __index = SInt32Decoder }
setmetatable( SInt32Decoder, { __index = Base } ) -- make it inherit from Base


function SInt32Decoder.new(pfield, tag, name)
    local new_class = Base.new("UINT32", pfield, tag, name)
    setmetatable( new_class, SInt32Decoder_mt )
    return new_class
end


function SInt32Decoder:decode(decoder)
    -- a FLOAT is encoded in little endian, fixed32 format
    return decoder:addFieldVarint32(self.pfield)
end


return SInt32Decoder
