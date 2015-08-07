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


-- verify float/double sizes are what we expect
do
    local test_str = "\000\230\064\070\046\255\085\073"
    local t = { Struct.unpack("<ff", test_str) }
    -- print(Struct.tohex(Struct.pack("<f", 12345.5 )))
    -- print(Struct.unpack("<f", "\000\230\064\070"))
    assert(t[1] == 12345.5 and t[2] == 876530.875 and t[3] == 9,
           "Your system does not use 4 bytes for 'float' types")

    test_str = "\174\071\225\122\012\036\254\064\102\102\102\224\041\140\151\065"
    t = { Struct.unpack("<dd", test_str) }
    assert(t[1] == 123456.78 and t[2] == 98765432.1 and t[3] == 17,
           "Your system does not use 8 bytes for 'double' types")
end




----------------------------------------
-- DoubleDecoder class, for "Message" statements
--
local DoubleDecoder = {}
local DoubleDecoder_mt = { __index = DoubleDecoder }
setmetatable( DoubleDecoder, { __index = Base } ) -- make it inherit from Base


function DoubleDecoder.new(pfield, tag, name)
    local new_class = Base.new("DOUBLE", pfield, tag, name)
    setmetatable( new_class, DoubleDecoder_mt )
    return new_class
end


function DoubleDecoder:decode(decoder)
    -- a DOUBLE is encoded in little endian, fixed64 format
    return decoder:addFieldStruct(self.pfield, "<d", 8)
end


return DoubleDecoder
