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
-- Int32Decoder class, for "int32" varint fields
--
local Int32Decoder = {}
local Int32Decoder_mt = { __index = Int32Decoder }
setmetatable( Int32Decoder, { __index = Base } ) -- make it inherit from Base


function Int32Decoder.new(pfield, tag, name)
    local new_class = Base.new("INT32", pfield, tag, name)
    setmetatable( new_class, Int32Decoder_mt )
    return new_class
end


function Int32Decoder:decode(decoder)
    return decoder:addFieldVarintSigned32(self.pfield)
end


return Int32Decoder
