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
-- BytesDecoder class, for unknown bytes in LENGTH_DELIMITED fields
--
local BytesDecoder = {}
local BytesDecoder_mt = { __index = BytesDecoder }
setmetatable( BytesDecoder, { __index = Base } ) -- make it inherit from Base



function BytesDecoder.new(pfield)
    local new_class = Base.new("LENGTH_DELIMITED", pfield)
    setmetatable( new_class, BytesDecoder_mt )
    return new_class
end


function BytesDecoder:decode(decoder, tag)
    dprint2("BytesDecoder:decode() called")
    return decoder:addFieldBytes(self.pfield)
end


return BytesDecoder
