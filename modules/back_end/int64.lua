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
-- Int64Decoder class, for "int64" varint fields
--
local Int64Decoder = {}
local Int64Decoder_mt = { __index = Int64Decoder }
setmetatable( Int64Decoder, { __index = Base } ) -- make it inherit from Base


function Int64Decoder.new(pfield, tag, name)
    local new_class = Base.new("INT64", pfield, tag, name)
    setmetatable( new_class, Int64Decoder_mt )
    return new_class
end


function Int64Decoder:decode(decoder)
    return decoder:addFieldVarintSigned64(self.pfield)
end


return Int64Decoder
