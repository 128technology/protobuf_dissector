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


local Prefs = {}


local range_rgx = GRegex.new("([0-9]+)\\s*(?:-\\s*([0-9]+))?")
local function getRange(range)
    local t = {}
    for first, second in GRegex.gmatch(range, range_rgx) do
        if first then
            first = tonumber(first)
            if second then
                second = tonumber(second)
                for port=first, second do
                    t[port] = true
                end
            else
                t[first] = true
            end
        end
    end
    return t
end


function Prefs:create(proto)
    dassert(proto, "Programming error: Prefs:create() called without created Proto")

    -- local udp_ports = self.udp_ports
    local udp_ports = "0"
    proto.prefs.udp_ports = Pref.range("UDP port range for protocol", udp_ports, "The range of UDP port numbers to decode the protocol for", 65535)

    -- this creates a new function, so the local udp_ports variable is saved as an
    -- upvalue and does not need to be stored in the self/proto object
    proto.prefs_changed = function()
        if udp_ports ~= proto.prefs.udp_ports then
            -- remove old ports, if not 0
            if udp_ports ~= "0" then
                for port in pairs(getRange(udp_ports)) do
                    DissectorTable.get("udp.port"):remove(port, proto)
                end
            end

            -- save new range
            udp_ports = proto.prefs.udp_ports

            -- add new ports, if not 0
            if udp_ports ~= "0" then
                for port in pairs(getRange(udp_ports)) do
                    DissectorTable.get("udp.port"):add(port, proto)
                end
            end
        end
    end
end


return Prefs
