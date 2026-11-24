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


local Prefs = {}


local function getRange(range)
    local t = {}
    local range_values = {}
    for first, last in range:gmatch("(%d+)%s*%-%s*(%d+)") do
        first = tonumber(first)
        last = tonumber(last)
        range_values[first] = true
        range_values[last] = true
        for port = first, last do
            t[port] = true
        end
    end
    for value in range:gmatch("%d+") do
        local port = tonumber(value)
        if not range_values[port] then
            t[port] = true
        end
    end
    return t
end


function Prefs:create(proto, extra_prefs_changed)
    dassert(proto, "Programming error: Prefs:create() called without created Proto")

    -- local udp_ports = self.udp_ports
    local udp_ports = "0"
    proto.prefs.udp_ports = Pref.range("UDP port range for protocol", udp_ports, "The range of UDP port numbers to decode the protocol for", 65535)

    local tcp_ports = "0"
    proto.prefs.tcp_ports = Pref.range("TCP port range for protocol", tcp_ports, "The range of TCP port numbers to decode the protocol for", 65535)

    -- how to delimit individual protobuf messages within a TCP byte stream;
    -- one of "none" (no desegmentation, each PDU is one message), "length32"
    -- (4-byte big-endian length prefix), or "varint" (protobuf-varint-style
    -- length prefix); see generic.tcp_framing for details
    proto.prefs.tcp_framing = Pref.string("TCP framing", "none",
        "How protobuf messages are delimited within a TCP stream: " ..
        "\"none\" (no desegmentation), \"length32\" (4-byte big-endian " ..
        "length prefix), or \"varint\" (protobuf-varint length prefix)")

    -- this creates a new function, so the local udp_ports/tcp_ports variables
    -- are saved as upvalues and do not need to be stored in the self/proto object
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

        if tcp_ports ~= proto.prefs.tcp_ports then
            -- remove old ports, if not 0
            if tcp_ports ~= "0" then
                for port in pairs(getRange(tcp_ports)) do
                    DissectorTable.get("tcp.port"):remove(port, proto)
                end
            end

            -- save new range
            tcp_ports = proto.prefs.tcp_ports

            -- add new ports, if not 0
            if tcp_ports ~= "0" then
                for port in pairs(getRange(tcp_ports)) do
                    DissectorTable.get("tcp.port"):add(port, proto)
                end
            end
        end

        -- Proto's "prefs_changed" is a write-only callback setter - it
        -- can't be read back to chain additional behavior onto it - so
        -- any extra logic (e.g. the generic fallback Proto's "SSR
        -- protobuf directory" handling) must be injected here instead
        if extra_prefs_changed then
            extra_prefs_changed()
        end
    end
end


return Prefs
