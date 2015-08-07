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


----------------------------------------
-- PFieldInfo module, for generating the tag/wiretap/length tree items
--
local PFieldInfo = {}

PFieldInfo.pfields = {}


function PFieldInfo:register(name, pfield)
    assert(not PFieldInfo.pfields[name], "Programming error: pfield name already exists: " .. name)
    PFieldInfo.pfields[name] = pfield
end


function PFieldInfo:getFields()
    --assert(#PFieldInfo.pfields > 1, "Protobuf Field info not registered yet")
    return PFieldInfo.pfields
end


return PFieldInfo
