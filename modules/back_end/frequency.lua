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

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror

--------------------------------------------------------------------------------
-- Frequency class, for handling repeated/optional/required/oneof
--
--
-- This class is optimized for speed during run-time (i.e., packet
-- dissection). There are a lot of tables and they're organized and looped
-- through in slghtly unatural ways in order to optimize for speed.
--
-- The way this works is it creates a table array, of sub-tables which contain
-- numbers representing counts. This is the 'tag_counts' table. Its size
-- depends on the number of tags which are ONEOF type, because the whole group
-- of ONEOF tags for the same ONEOF name share the same tag_counts sub-table
-- count. The OPTIONAL, REQUIRED, and REPEATED tags get their own counting
-- sub-table in tag_counts.
--
-- It creates a 'tags' table indexed by tag number, and the value points to
-- the sub-table entry in tag_counts table. And another 'singles' table
-- indexed by tag, for tags of optional/required/oneof (i.e., not repeated).
--
-- So during a checkTag(), it looks up the given tag in the 'tags' table, and
-- increments the count. It then looks up the 'single' table, and decides if
-- the tag's count is invalid due to a required/optional/oneof being more than
-- count of 1.
--
-- There is also a 'oneof_names' table indexed by tags, and a 'labels' table
-- indexed by tags, with the value being the label type of the given tag; both
-- of these are used for adding the protofield or expert info after the
-- counting check.
--
-- For the checkMessage(), it has yet another 'required' table, indexed by the
-- tag names that are required or oneof, with the table values also being
-- pointers to the tag_counts table entries. It uses this to verify each
-- required/oneof tag has a count > 0.
--
-- During a reset(), it goes through the tag_counts table resetting the count
-- to 0.
--
local Frequency = {}
local Frequency_mt = { __index = Frequency }


-- gets or creates a new count sub-table in tag_counts based on 'key', which
-- is either the tag number or oneof name; a temporary table is used to keep
-- track of these keys, so that we don't create more than one count for the
-- same oneof group name
function Frequency:getCounter(key)
    if not self.temp_keyed_counts then
        self.temp_keyed_counts = {}
    end
    local temp_keyed_counts = self.temp_keyed_counts
    local tag_counts = self.tag_counts

    if temp_keyed_counts[key] then
        return temp_keyed_counts[key]
    end

    local t = { [1] = 0 }
    tag_counts[#tag_counts+1] = t
    temp_keyed_counts[key] = t
    return t
end


function Frequency:addTagValueToTable(table_name, tag, value)
    dassert(not self[table_name][tag], "Programming error: tag already exists in", table_name, " table:", tag)
    self[table_name][tag] = value
end


function Frequency:addLabel(tag, label)
    return self:addTagValueToTable("labels", tag, label)
end


function Frequency:addOneofName(tag, oneof_name)
    return self:addTagValueToTable("oneof_names", tag, oneof_name)
end


function Frequency:addTagCounter(tag, counter)
    return self:addTagValueToTable("tags", tag, counter)
end


function Frequency:addSingle(tag, counter)
    return self:addTagValueToTable("single", tag, counter)
end


function Frequency:addRequired(name, counter)
    return self:addTagValueToTable("required", name, counter)
end


local label_is_single = {
    ["REQUIRED"] = true,
    ["OPTIONAL"] = true,
    ["ONEOF"]    = true,
}


local label_is_required = {
    ["REQUIRED"] = true,
    ["ONEOF"]    = true,
}


function Frequency:init(tag_dispatch_tbl)
    for tag, object in pairs(tag_dispatch_tbl) do
        local counter
        local label = object:getLabel()
        dassert(label, "Programming error: did not get label for:", object:getName())

        self:addLabel(tag, label)

        -- print("Got label:" .. label .. ", for name=" .. object:getName())
        if label == "ONEOF" then
            local oneof_name = object:getOneofName()
            dassert(oneof_name, "Programming error: could not get oneof name for object:", object:getName())
            self:addOneofName(oneof_name)
            counter = self:getCounter(oneof_name)
        else
            counter = self:getCounter(tag)
        end

        self:addTagCounter(tag, counter)

        if label_is_single[label] then
            self:addSingle(tag, counter)
        end

        if label_is_required[label] then
            -- print("Adding required label=" .. label .. ", for name=" .. object:getName())
            self:addRequired(object:getName(), counter)
        end
    end
    -- clear temp tables
    self.temp_keyed_counts = nil
end


function Frequency.new(tag_dispatch_tbl)
    local new_class = { -- the new instance
        ["tag_counts"]  = {},
        ["labels"]      = {},
        ["oneof_names"] = {},
        ["tags"]        = {},
        ["single"]      = {},
        ["required"]    = {},
    }
    setmetatable( new_class, Frequency_mt )
    new_class:init(tag_dispatch_tbl)
    return new_class
end


function Frequency:checkTag(tag)
    local counter = self.tags[tag]
    dassert(counter, "Programming error: counter not found for tag:", tag)

    local count = counter[1]

    count = count + 1
    counter[1] = count

    if count > 1 and self.single[tag] then
        local label = self.labels[tag]
        dassert(label, "Programming error: label not found for tag:", tag)
        if label == "ONEOF" then
            dassert(self.oneof_names[tag], "Programming error: no oneof name for tag: ", tag)
            return nil, "multiple_oneof", self.oneof_names[tag]
        end
        return nil, "multiple_single"
    end

    return true
end


function Frequency:checkMessage()
    local required, t = self.required
    for name, counter in pairs(required) do
        if counter[1] == 0 then
            if not t then t = {} end
            t[#t+1] = name
        end
    end

    if t then
        return nil, "missing_required", table.concat(t, ", ")
    end

    return true
end


function Frequency:reset()
    local counters = self.tag_counts
    local sz = #counters
    for i=1, sz do
        counters[i][1] = 0
    end
end


return Frequency
