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
    This script is a Lua module (not stand-alone) for handling proto files.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

]]----------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end


local Settings  = require "settings"
local dprint    = Settings.dprint
local dprint2   = Settings.dprint2
local dassert   = Settings.dassert


----------------------------------------
-- our module table that we return to the caller of this script
local FileReader = {}

function FileReader:reset()
    self.results = {}
end

function FileReader:read(name)
end

local filepath_rgx = GRegex.new("^(.*)([^/\\\\]+)$", "U")


--------------------------------------------------------------------------------
-- the public functions of the module

-- returns a separated path and file name
function FileReader:getPathFileNames(filename)
    return filepath_rgx:match(filename)
end

-- opens and reads a single filename, returns chunk
function FileReader:loadFile(name)
    local file, err = io.open(name, "r")
    dassert(file, "Error opening file:", name, "\nError message:", err)

    local output, err2 = file:read("*all")
    dassert(output, "Error reading file:", name, "\nError message:", err2)

    file:close()

    -- remove carriage-return, so it's just linefeeds, and save it
    return string.gsub(output, "\r", "")
end


-- opens and reads the files identified in the filenames table
-- returns a table of the string contents, indexed by filename
-- with the string chunk in a "chunk" sub-table entry
function FileReader:loadFiles(filenames)
    local proto_files = {}

    for _, name in ipairs(filenames) do
        local path, filename = self:getPathFileNames(name)
        dprint2("Got path=", path, "filename=", filename)

        dassert(filename, "Could not determine filename portion of:", name)
        dassert(not proto_files[filename], "Asked to read a filename that's already been read")

        proto_files[filename] = { chunk = self:loadFile(name), ["path"] = path }
    end
    return proto_files
end




return FileReader
