----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
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


--------------------------------------------------------------------------------
-- The Cursor class for keeping track of position in files while lexing/parsing
-- to enable useful error messages and such
--
local Cursor = {}
local Cursor_mt = { __index = Cursor }


function Cursor.new(file_name, file_text, line, column, absolute)
    line     = line or 1
    column   = column or 1
    absolute = absolute or 1

    local new_class = {  -- the new instance
        ["line"]      = line,
        ["column"]    = column,
        ["absolute"]  = absolute,
        ["file_name"] = file_name,
        ["file_text"] = file_text,
    }
    setmetatable( new_class, Cursor_mt )
    return new_class
end


function Cursor:getType()
    return "CURSOR"
end


function Cursor:clone()
    return self.new(self.file_name, self.file_text, self.line, self.column, self.absolute)
end


function Cursor:getLine()
    return self.line
end


function Cursor:getColumn()
    return self.column
end


function Cursor:getFileName()
    return self.file_name
end


function Cursor:getFileText()
    return self.file_text
end


function Cursor:getDebugOutput()
    return self.file_name .. ":" .. self.line .. ":"
end


function Cursor:advance(columns)
    self.column = self.column + columns
    self.absolute = self.absolute + columns
end


function Cursor:nextLine()
    self.line = self.line + 1
    self.absolute = self.absolute + 1
    self.column = 1
end


local len = string.len
local sub = string.sub


function Cursor:advanceText(text)
    if not text or len(text) == 0 then
        return
    end

    local newline_count = select(2, text:gsub("\n", ""))
    self.absolute = self.absolute + len(text)
    self.line = self.line + newline_count
    if newline_count > 0 then
        local last_newline = text:match(".*()\n")
        self.column = len(text) - last_newline + 1
    else
        self.column = self.column + len(text)
    end
end


function Cursor:skipWhitespace(whitespace)
    return self:advanceText(whitespace)
end



function Cursor:skipChunk(chunk)
    return self:advanceText(chunk)
end


-- given a remaining chunk of the file's text, advance the cursor
-- to that position
function Cursor:advanceToChunk(chunk)
    local chunk_len = len(chunk)
    local file_len  = len(self.file_text)
    local current   = self.absolute

    dassert(file_len - chunk_len >= current,
            "Programming error: wants to skip chunk len:", chunk_len,
            " but file len=", file_len, "and current=", current)

    self:skipChunk( sub(self.file_text, current, file_len - chunk_len) )
end




return Cursor
