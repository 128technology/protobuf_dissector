-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local my_info = {
        version   = "1.0",
        author    = "Hadriel Kaplan",
        email     = "hadriel@128technology.com",
        copyright = "Copyright (c) 2015, 128 Technology, Inc.",
        license   = "MIT license",
        details   = "This is a plugin for Wireshark, to dissect Google protobuf messages.",
        help      = [[
    HOW TO RUN THIS SCRIPT:
    
    Wireshark and Tshark support multiple ways of loading Lua scripts: through
    a dofile() call in init.lua, through the file being in either the global
    or personal plugins directories, or via the command line. The latter two
    methods are the best: either copy this script into your "Personal Plugins"
    directory, or load it from the command line.

    This script also needs to know where to find your '.proto' files. There are
    two ways of accomplishing that:
        1. Add it to the "ProtoFileNames" table inside this script, or...
        2. Add it as a command-line argument(s). This only works if this protobuf.lua
           script is also loaded through the command line. For example:
          wireshark -X lua_script:protobuf.lua -X lua_script1:foo.proto -X lua_script1:bar.proto
    ]]
    }
    set_plugin_info(my_info)
end


--------------------------------------------------------------------------------
-- a table of protobuf '.proto' files to load
local ProtoFileNames = {
    -- example:
    -- "foo.proto", "bar.proto"
}

-- allow the command line to specify file names
for _, n in ipairs({ ... }) do
    ProtoFileNames[#ProtoFileNames + 1] = n
end


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 0,    -- default UDP port number to dissect
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()


-- load our modules
dprint("Requiring modules")

package.prepend_path("modules")

local GenericProto  = require "generic.proto"
local Compiler = require "compiler"

dprint("modules loaded")


-- initialize the compiler
Compiler:init()


----------------------------------------
-- load the proto file contents
dprint2(#ProtoFileNames,"proto files being compiled")


----------------------------------------
-- compile the proto files
local decoder_table = Compiler:compile(ProtoFileNames, default_settings.debug_level == debug_level.LEVEL_2, dprint2)


