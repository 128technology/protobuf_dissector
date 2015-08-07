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


local inspect = require "inspect"
local debug   = require "debug"


--------------------------------------------------------------------------------
-- our Settings
local Settings = {

    -- a table of protobuf '.proto' files to load
    proto_files = {
        -- example:
        -- "foo.proto", "bar.proto"
    },

    -- debug levels
    dlevel = {
        DISABLED = 0,
        LEVEL_1  = 1,
        LEVEL_2  = 2
    },

    -- current debug level; default disabled
    debug_level = 0,

    -- debug printers for different debug levels, by default they
    -- do nothing; but this will be updated later
    dprint  = function() end,
    dprint2 = function() end,


}

----------------------------------------

local inspect_filter = inspect.makeFilter({ ".<metatable>" })

local function generateOutput(t)
    local out = {}

    for _, value in ipairs(t) do
        local vt = type(value)
        if vt == 'string' then
            out[#out+1] = value
        elseif vt == 'table' then
            out[#out+1] = "\n" .. inspect(value, { filter = inspect_filter })
        else
            out[#out+1] = tostring(value)
        end
    end
    return table.concat(out, " ")
end


local function resetDebugLevel()
    if Settings.debug_level > Settings.dlevel.DISABLED then
        Settings.dprint = function(...)
            info( generateOutput( { "Protobuf-Debug:", ... } ) )
        end

        if Settings.debug_level > Settings.dlevel.LEVEL_1 then
            Settings.dprint2 = Settings.dprint
        end
    else
        Settings.dprint = function() end
        Settings.dprint2 = function() end
    end
end
-- call it now
resetDebugLevel()


--------------------------------------------------------------------------------
-- the public functions of the module

function Settings:processCmdLine(args)
    -- allow the command line to specify file names, debug level
    for _, n in ipairs(args) do
        if n:find("=") then
            local level = n:match("debug%s*=%s*(%d)")
            if not level then
                error("Bad argument given to protobuf.lua: " .. n)
            end
            self.debug_level = tonumber(level)
        else
            self.proto_files[#self.proto_files + 1] = n
        end
    end
    resetDebugLevel()
end


function Settings:getProtoFileNames()
    return self.proto_files
end


function Settings:getDebugLevel()
    return self.debug_level
end


-- like Lua's 'assert()', except it takes an arbitrary number of arguments
-- which it will concatenate into an error string if the first argument is
-- false; this way we avoid the performance penalty of generating strings
-- for non-false assertions
function Settings.dassert(check, ...)
    if check then return check end
    error( debug.traceback(generateOutput({ "Protobuf-ERROR:", ... }), 2 ), 2 )
end


function Settings.derror(...)
    error( debug.traceback(generateOutput({ "Protobuf-ERROR:", ... }), 2 ), 2 )
end



return Settings
