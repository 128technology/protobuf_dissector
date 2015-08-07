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
-- BoolDecoder class, for "int32" varint fields
--
local BoolDecoder = {}
local BoolDecoder_mt = { __index = BoolDecoder }
setmetatable( BoolDecoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase


function BoolDecoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("INT32", pfield, tag, name)
    setmetatable( new_class, BoolDecoder_mt )
    return new_class
end


function BoolDecoder:decode(decoder)
    return decoder:addFieldBool(self.pfield)
end


return BoolDecoder
