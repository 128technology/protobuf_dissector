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


-- verify float/double sizes are what we expect
do
    local test_str = "\000\230\064\070\046\255\085\073"
    local t = { Struct.unpack("<ff", test_str) }
    -- print(Struct.tohex(Struct.pack("<f", 12345.5 )))
    -- print(Struct.unpack("<f", "\000\230\064\070"))
    assert(t[1] == 12345.5 and t[2] == 876530.875 and t[3] == 9,
           "Your system does not use 4 bytes for 'float' types")
end




----------------------------------------
-- FloatDecoder class, for "Message" statements
--
local FloatDecoder = {}
local FloatDecoder_mt = { __index = FloatDecoder }
setmetatable( FloatDecoder, { __index = DecoderBase } ) -- make it inherit from DecoderBase
--back_end:registerClass("FLOAT", "FloatDecoder", FloatDecoder)



function FloatDecoder.new(pfield, tag, name)
    local new_class = DecoderBase.new("FLOAT", pfield, tag, name)
    setmetatable( new_class, FloatDecoder_mt )
    return new_class
end


function FloatDecoder:decode(decoder)
    -- a FLOAT is encoded in little endian, fixed32 format
    decoder:addFieldStruct(self.pfield, "<f", 4)
end


return FloatDecoder
