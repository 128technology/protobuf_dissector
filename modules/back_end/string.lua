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
-- StringDecoder class, for "string" length-encoded fields
--
local StringDecoder = {}
local StringDecoder_mt = { __index = StringDecoder }
setmetatable( StringDecoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase


function StringDecoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("STRING", pfield, tag, name)
    setmetatable( new_class, StringDecoder_mt )
    return new_class
end


function StringDecoder:decode(decoder)
    return decoder:addFieldString(self.pfield)
end


return StringDecoder
