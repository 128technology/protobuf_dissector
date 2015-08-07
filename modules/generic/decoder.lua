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

--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local GenericDecoder = {}


GenericDecoder.decoders = {}

function GenericDecoder:register(wtype, decoder)
    assert(not GenericDecoder.decoders[wtype], "Programming error: generic decoder already registered: " .. wtype)
    GenericDecoder.decoders[wtype] = decoder
end


function GenericDecoder:decode(decoder, tag, wtype)
    return GenericDecoder.decoders[wtype]:decode(decoder, tag)
end


return GenericDecoder
