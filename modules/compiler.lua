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

--[[
    This script is a Lua module (not stand-alone) for compiling proto files.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

        2. The second phase, called the "import" phase, performs the import of
           other proto files. If the file to be imported is already in the
           single table key'ed by filename, then it does not import it again.
           If the file is not in the big table, then it is read in, lex'ed,
           goes through the "build" phase, and added to the big table of
           filenames, so that another proto file importing the same (common)
           protof file does not create two separate ASTs for the common one.

]]----------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end


-- load our modules
local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert

local FrontEnd = require "front_end.front_end"
local BackEnd  = require "back_end.back_end"


----------------------------------------
-- our module table that we return to the caller of this script
local compiler = {}


--------------------------------------------------------------------------------
-- the public functions of the module


function compiler:reset()
    self.ast = nil
end


function compiler:init()
    FrontEnd:init()
end


local function display(tbl)
    print(inspect(tbl, { filter = inspect.makeFilter({ ".<metatable>" }) }))
end


function compiler:compile(proto_filenames)
    self:reset()

    local global_ast = FrontEnd:execute(proto_filenames)
    dassert(global_ast, "Front-end failed to return an AST")

    dprint2("The generated AST:\n", global_ast)

    local decode_table = BackEnd:execute(global_ast)

    global_ast = nil
    collectgarbage()

    dprint2("The generated decoder table:", decode_table)

    return decode_table
end


return compiler
