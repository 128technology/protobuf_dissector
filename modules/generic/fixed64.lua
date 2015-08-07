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

local Base = require "generic.base"


----------------------------------------
-- Fixed64Decoder class, for "fixed64" fields
--
local Fixed64Decoder = {}
local Fixed64Decoder_mt = { __index = Fixed64Decoder }
setmetatable( Fixed64Decoder, { __index = Base } ) -- make it inherit from Base



function Fixed64Decoder.new(pfield)
    local new_class = Base.new("FIXED32", pfield)
    setmetatable( new_class, Fixed64Decoder_mt )
    return new_class
end


function Fixed64Decoder:decode(decoder, tag)
    dprint2("Fixed64Decoder:decode() called")
    return decoder:addFieldStruct(self.pfield, "<E", 8)
end


return Fixed64Decoder
