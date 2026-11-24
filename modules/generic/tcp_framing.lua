----------------------------------------
--
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
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
-- Framing module: wraps a Proto's "dissect one message" function with TCP
-- stream reassembly, based on the Proto's own "tcp_framing" preference.
--
-- Protobuf messages have no inherent length-prefix or other framing of their
-- own (that's why UDP, with its own packet boundaries, "just works"); but
-- when carried over TCP, something has to delimit where one message ends and
-- the next begins, since TCP is just a byte stream. This module supports the
-- two most common conventions:
--
--   "none"     - no desegmentation is attempted; each TCP segment/PDU, as
--                delivered to this dissector, is treated as exactly one
--                complete protobuf message (the original/legacy behavior;
--                suitable only if some lower layer already provides framing)
--   "length32" - each message is prefixed by a 4-byte unsigned big-endian
--                length field giving the size, in bytes, of the message
--                that immediately follows it
--   "varint"   - each message is prefixed by its length encoded the same
--                way protobuf itself encodes "VARINT" fields (a base-128,
--                little-endian group of 7-bit digits)
--
--------------------------------------------------------------------------------
local Framing = {}


-- reads a protobuf-style varint length prefix out of 'tvbuf' starting at
-- byte offset 'offset' (0-based), stopping at 'limit' (exclusive); returns
-- true, value, number-of-bytes-consumed on success, or false if there
-- weren't enough bytes available yet (i.e., need more data from TCP)
function Framing.readVarintLength(tvbuf, offset, limit)
    local value = 0
    local shift = 0
    local idx = offset

    while idx < limit do
        local byte = tvbuf(idx, 1):uint()
        value = value + ((byte % 0x80) * (2 ^ shift))
        idx = idx + 1

        if byte < 0x80 then
            return true, value, (idx - offset)
        end

        shift = shift + 7
        if shift > 63 then
            -- malformed: varint is absurdly long; give up rather than loop
            -- forever waiting for more segments
            derror("Protobuf TCP framing: varint length prefix is too long (malformed stream)")
        end
    end

    -- ran out of bytes before finding the terminating byte
    return false
end


-- wraps 'dissect_message', a function with the signature
-- (tvbuf, pktinfo, root) that dissects exactly one complete protobuf message
-- starting at the beginning of the given Tvb, and returns a Proto.dissector
-- compatible function that adds TCP length-prefix framing/reassembly on top
-- of it, driven by proto.prefs.tcp_framing (only when running over TCP;
-- UDP traffic is passed straight through unchanged, since UDP already
-- provides its own message boundaries)
function Framing.wrap(proto, dissect_message)
    return function(tvbuf, pktinfo, root)
        -- pktinfo.can_desegment is only truthy for reassembly-capable
        -- transports (i.e., TCP); for UDP (and anything else) just
        -- dissect the one message directly, same as before TCP support
        -- was added
        if not pktinfo.can_desegment then
            return dissect_message(tvbuf, pktinfo, root)
        end

        local framing = proto.prefs.tcp_framing

        if not framing or framing == "none" then
            return dissect_message(tvbuf, pktinfo, root)
        end

        local buf_len = tvbuf:len()
        local offset = 0

        while offset < buf_len do
            local header_len, msg_len

            if framing == "length32" then
                if (buf_len - offset) < 4 then
                    pktinfo.desegment_offset = offset
                    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                    return
                end
                header_len = 4
                msg_len = tvbuf(offset, 4):uint()

            elseif framing == "varint" then
                local ok, vlen, vsize = Framing.readVarintLength(tvbuf, offset, buf_len)
                if not ok then
                    pktinfo.desegment_offset = offset
                    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                    return
                end
                header_len = vsize
                msg_len = vlen

            else
                -- unrecognized preference value: behave as if "none"
                return dissect_message(tvbuf, pktinfo, root)
            end

            if (buf_len - offset) < (header_len + msg_len) then
                -- not enough bytes yet for the full message; ask for more
                pktinfo.desegment_offset = offset
                pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                return
            end

            local msg_tvb = tvbuf(offset + header_len, msg_len):tvb()
            dissect_message(msg_tvb, pktinfo, root)

            offset = offset + header_len + msg_len
        end

        return offset
    end
end


return Framing
