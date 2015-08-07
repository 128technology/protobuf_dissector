----------------------------------------
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, 128 Technology, Inc.
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------
--[[

    This script is a Lua module (not stand-alone) for handling the "back-end"
    of the compiler. In this module's case, it coordinates/controls the
    creation of the Proto/ProtoField/Prefs for each Message "protocol", and
    generates run-time code to decode/dissect them; but the actual work is
    mostly performed in the AST nodes.

    This module follows the classic Lua module method of storing its public
    methods/functions in a table and passing back the table to the caller of
    this module file.

]]


local syntax = require "syntax"


local back_end = {}


back_end.ttype_to_decoder_class = {}


-- registers classes in classname index, and their ttype in ttype_to_decoder_class
function back_end.registerClass(ttype, classname, class)
    assert(not back_end[classname], "Programming error: Back-end class " .. classname .. " already registered")
    back_end[classname] = class

    if ttype then
        assert(syntax:isTokenTtype(ttype), "Programming error: passed-in type is not a ttype: " .. ttype)
        assert(not back_end.ttype_to_decoder_class[ttype], "Programming error: Class ttype " .. ttype .. " already registered for decoder")
        back_end.ttype_to_decoder_class[ttype] = class
    end
end

require "back_end.double"


function back_end:execute(global_ast)
    -- creates Protos, ProtoFields
    local proto_table = {}
    global_ast:createProtocols(proto_table)

    return proto_table
end

return back_end
