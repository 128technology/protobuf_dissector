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
-- Fixed32Decoder class, for "fixed32" fields
--
local Fixed32Decoder = {}
local Fixed32Decoder_mt = { __index = Fixed32Decoder }
setmetatable( Fixed32Decoder, { __index = Base } ) -- make it inherit from Base



function Fixed32Decoder.new(pfield)
    local new_class = Base.new("FIXED32", pfield)
    setmetatable( new_class, Fixed32Decoder_mt )
    return new_class
end


function Fixed32Decoder:decode(decoder, tag)
    dprint2("Fixed32Decoder:decode() called for tag:", tag)
    return decoder:addFieldStruct(self.pfield, "<I4", 4)
end


return Fixed32Decoder
