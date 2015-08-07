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

local DecoderBase = require "back_end.decoder_base"


----------------------------------------
-- Int32Decoder class, for "int32" fields
--
local Int32Decoder = {}
local Int32Decoder_mt = { __index = Int32Decoder }
setmetatable( Int32Decoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase
--back_end:registerClass("FLOAT", "Int32Decoder", Int32Decoder)



function Int32Decoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("INT32", pfield, tag, name)
    setmetatable( new_class, Int32Decoder_mt )
    return new_class
end


function Int32Decoder:decode(decoder)
    -- a FLOAT is encoded in little endian, fixed32 format
    decoder:addFieldVarintSigned32(self.pfield)
end


return Int32Decoder
