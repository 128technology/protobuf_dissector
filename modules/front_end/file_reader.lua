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
    This script is a Lua module (not stand-alone) for handling proto files.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

]]----------------------------------------

-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end

----------------------------------------
-- our module table that we return to the caller of this script
local M = {}

function M:reset()
    self.results = {}
end

function M:read(name)
end

local filepath_rgx = GRegex.new("^(.*)([^/\\\\]+)$", "U")


--------------------------------------------------------------------------------
-- the public functions of the module

-- returns a separated path and file name
function M:getPathFileNames(filename)
    return filepath_rgx:match(filename)
end

-- opens and reads a single filename, returns chunk
function M:loadFile(name)
    local file, err = io.open(name, "r")
    assert(file, "Error opening file: " .. name .. "\nError message: " .. tostring(err))

    local output, err2 = file:read("*all")
    assert(output, "Error reading file: " .. name .. "\nError message: " .. tostring(err2))

    file:close()

    -- remove carriage-return, so it's just linefeeds, and save it
    return string.gsub(output, "\r", "")
end


-- opens and reads the files identified in the filenames table
-- returns a table of the string contents, indexed by filename
-- with the string chunk in a "chunk" sub-table entry
function M:loadFiles(filenames, do_debug, pfunc)
    local proto_files = {}

    for _, name in ipairs(filenames) do
        local path, filename = self:getPathFileNames(name)
        if do_debug then
            pfunc("Got path=", path, "filename=", filename)
        end
        assert(filename, "Could not determine filename portion of:" .. name)
        assert(not proto_files[filename], "Asked to read a filename that's already been read")

        proto_files[filename] = { chunk = self:loadFile(name), ["path"] = path }
    end
    return proto_files
end


-- dumps a ProtoFiles table of file content
-- 'pfunc' must be a print-style function (print, dprint, dprint2)
function M:dump(pfunc, proto_files)
    pfunc("\n\nResults table:")
    if proto_files and #proto_files > 0 then
        for name, subtbl in pairs(proto_files) do
            if subtbl.chunk then
                pfunc(name, "= \nbegin [[\n", subtbl.chunk, "\n]] end")
            else
                pfunc(name, "missing chunk")
            end
        end
    end
    pfunc("End of results table\n\n")
end

return M
