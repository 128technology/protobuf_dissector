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

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror

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


-- verify float/double sizes are what we expect
do
    local test_str = "\000\230\064\070\046\255\085\073"
    local t = { Struct.unpack("<ff", test_str) }
    -- print(Struct.tohex(Struct.pack("<f", 12345.5 )))
    -- print(Struct.unpack("<f", "\000\230\064\070"))
    assert(t[1] == 12345.5 and t[2] == 876530.875 and t[3] == 9,
           "Your system does not use 4 bytes for 'float' types")
end




local decoder_func = {
    ["DOUBLE"]    = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<d", 8)
                    end,

    ["FLOAT"]     = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<f", 4)
                    end,

    ["FIXED32"]   = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<I4", 4)
                    end,

    ["FIXED64"]   = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<E", 8)
                    end,

    ["SFIXED32"]  = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<i4", 4)
                    end,

    ["SFIXED64"]  = function (object, decoder)
                        return decoder:addFieldStruct(object.pfield, "<e", 8)
                    end,

    ["INT32"]     = function (object, decoder)
                        return decoder:addFieldVarintSigned32(object.pfield)
                    end,

    ["INT64"]     = function (object, decoder)
                        return decoder:addFieldVarintSigned64(object.pfield)
                    end,

    ["SINT32"]    = function (object, decoder)
                        return decoder:addFieldVarintZigZag32(object.pfield)
                    end,

    ["SINT64"]    = function (object, decoder)
                        return decoder:addFieldVarintZigZag64(object.pfield)
                    end,

    ["UINT32"]    = function (object, decoder)
                        return decoder:addFieldVarint32(object.pfield)
                    end,

    ["UINT64"]    = function (object, decoder)
                        return decoder:addFieldVarint64(object.pfield)
                    end,

    ["STRING"]    = function (object, decoder)
                        return decoder:addFieldString(object.pfield)
                    end,

    ["BOOL"]      = function (object, decoder)
                        return decoder:addFieldBool(object.pfield)
                    end,

    ["BYTES"]     = function (object, decoder)
                        return decoder:addFieldBytes(object.pfield)
                    end,
}


----------------------------------------
-- NativeDecoder class, for "fixed32" fields
--
local NativeDecoder = {}
local NativeDecoder_mt = { __index = NativeDecoder }
setmetatable( NativeDecoder, { __index = Base } ) -- make it inherit from Base


function NativeDecoder.new(ttype, pfield, tag, name, label, oneof_name)
    local new_class = Base.new("FIXED32", pfield, tag, name, label, oneof_name)
    dassert(decoder_func[ttype], "Programming error: No decoder function for ttype:", ttype)
    new_class["decode_func"] = decoder_func[ttype]
    setmetatable( new_class, NativeDecoder_mt )
    return new_class
end


function NativeDecoder:decode(decoder)
    return self:decode_func(decoder)
end


return NativeDecoder
