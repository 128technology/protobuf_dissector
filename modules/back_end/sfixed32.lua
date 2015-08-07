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
-- SFixed32Decoder class, for "sfixed32" fields
--
local SFixed32Decoder = {}
local SFixed32Decoder_mt = { __index = SFixed32Decoder }
setmetatable( SFixed32Decoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase


function SFixed32Decoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("SFIXED32", pfield, tag, name)
    setmetatable( new_class, SFixed32Decoder_mt )
    return new_class
end


function SFixed32Decoder:decode(decoder)
    return decoder:addFieldStruct(self.pfield, "<i4", 4)
end


return SFixed32Decoder
