-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local my_info = {
        version   = "1.0",
        author    = "Hadriel Kaplan",
        email     = "hadriel@128technology.com",
        copyright = "Copyright (c) 2015, 128 Technology, Inc.; Copyright (c) 2026 Hewlett Packard Enterprise Development LP.",
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


-- capture command line arguments
local args = { ... }


local version = get_version and get_version()
local major, minor = version and version:match("^(%d+)%.(%d+)")
if not major or tonumber(major) < 3 or (tonumber(major) == 3 and tonumber(minor) < 6) then
    error("Wireshark 3.6 or newer is required")
end


local source = debug.getinfo(1, "S").source
if source:sub(1, 1) ~= "@" then
    error("Unable to determine protobuf plugin path")
end
source = source:sub(2)

local separator = package.config:sub(1, 1)
local directory_end = 0
for position = 1, #source do
    if source:sub(position, position) == separator then
        directory_end = position
    end
end
local plugin_dir = directory_end > 0 and source:sub(1, directory_end - 1) or "."

local plugin_state = {
    ["__DIR__"] = plugin_dir,
    ["__DIR_SEPARATOR__"] = separator,
}
_G["protobuf_dissector"] = plugin_state
_G["protbuf_dissector"] = plugin_state

-- Reload Lua Plugins keeps this Lua state alive, so drop cached modules and
-- generated dissector guards before recompiling the proto files.
for module_name in pairs(package.loaded) do
    if module_name == "settings" or module_name == "compiler" or
       module_name == "syntax" or module_name == "prefs" or
       module_name == "inspect" or module_name == "ssr_bfd" or
       module_name == "svr" or module_name:match("^ast%.") or
       module_name:match("^front_end%.") or module_name:match("^back_end%.") or
       module_name:match("^generic%.") then
        package.loaded[module_name] = nil
    end
end

_G["ssr_bfd_proto"] = nil
_G["ssr_bfd_metadata_key_indices"] = nil
_G["svr_proto"] = nil

package.path = table.concat({
    plugin_dir .. separator .. "?.lua",
    plugin_dir .. separator .. "modules" .. separator .. "?.lua",
    package.path,
}, ";")


-- load our settings
local Settings = require "settings"
Settings:processCmdLine(args)
local dprint  = Settings.dprint
local dprint2 = Settings.dprint2


-- load the rest of our modules
local GenericProto  = require "generic.proto"

local Compiler = require "compiler"


dprint("Protobuf modules loaded")


-- initialize the compiler
Compiler:init()

local proto_files = Settings:getProtoFileNames()


----------------------------------------
-- load the proto file contents
dprint2(#proto_files,"proto files being compiled")


----------------------------------------
-- compile the proto files
local decoder_table = Compiler:compile(proto_files)

require "ssr_bfd"
require "svr"

-- disable loading of our modules
_G['protbuf_dissector'] = nil
