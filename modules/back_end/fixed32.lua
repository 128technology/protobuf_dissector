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

local DecoderBase = require "back_end.decoder_base"


----------------------------------------
-- Fixed32Decoder class, for "fixed32" fields
--
local Fixed32Decoder = {}
local Fixed32Decoder_mt = { __index = Fixed32Decoder }
setmetatable( Fixed32Decoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase


function Fixed32Decoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("FIXED32", pfield, tag, name)
    setmetatable( new_class, Fixed32Decoder_mt )
    return new_class
end


function Fixed32Decoder:decode(decoder)
    return decoder:addFieldStruct(self.pfield, "<I4", 4)
end


return Fixed32Decoder
