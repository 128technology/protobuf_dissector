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
    This script is a Lua module (not stand-alone) for protobuf varint decoding.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.
]]

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror

local bit = bit
local Struct = Struct

if not Struct then
    return nil, "Wireshark is too old: no Struct library"
end



local varint_struct_fmt = {}
-- fill with formats based on length
for length=1,11 do
    varint_struct_fmt[length] = string.rep("B",length)
end


-- get up to 5 byte numbers
local function getBytes32(buff, offset, length)
    return { Struct.unpack(varint_struct_fmt[length < 5 and length or 5], buff, offset+1) }
end


-- get up to 10 byte numbers
local function getBytes64(buff, offset, length)
    return { Struct.unpack(varint_struct_fmt[length < 10 and length or 10], buff, offset+1) }
end


local function unsign(n)
    if n < 0 then
        n = 4294967296 + n
    end
    return n
end




--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local varint = {}


--------------------------------------------------------------------------------
-- the public functions of the module


----------------------------------------
-- gets the key varint's tag and wiretype
--
-- this could have been done using varint:decode32() and then
-- masking/shifting, but it's used often enough that making
-- it a separate specific function seemed appropriate
function varint:decodeKey(buff, offset, length)
    local bytes = getBytes32(buff, offset, length)

    local first_byte = bytes[1]

    -- % 8 is same as masking all but last 3 bits (= & 0x07)
    local wiretype = first_byte % 8

    -- clear MSB, right-shift by 3
    local tag = bit.rshift( bit.band(first_byte, 0x7F), 3 )

    local size = 1
    local last = true

    -- optimized for only one byte, since that's super-common
    if first_byte > 127 then

        -- MSB bit is set, so there are more
        last = false
        local num_bits = 4

        for idx, byte in ipairs(bytes) do
            -- already handled the first one
            if idx > 1 then
                size = size + 1

                -- it's the last one if MSB is 0
                last = byte < 128

                -- clear MSB, if it's even set
                byte = byte % 128

                -- left shift by num_bits
                byte = bit.lshift(byte, num_bits)

                if byte < 0 then
                    -- bitop library quirk^M^M design
                    byte = unsign(byte)
                end

                tag = tag + byte

                if last then break end

                num_bits = num_bits + 7
            end
        end
    end

    -- 536870912 is 2^32 >> 3
    if last and tag < 536870912 then
        -- success
        return tag, wiretype, size
    end
end


----------------------------------------
-- returns Lua number of a 32-bit unsigned varint
function varint:decode32(buff, offset, length)
    local bytes = getBytes32(buff, offset, length)

    local value = 0

    for size, byte in ipairs(bytes) do
        -- it's the last one if MSB is 0
        local last = byte < 128

        -- clear MSB, if it's even set
        byte = byte % 128

        -- left shift by number of bytes * 7 bits per byte
        byte = bit.lshift(byte, (size - 1) * 7)

        if byte < 0 then
            -- bitop library quirk^M^M design
            byte = unsign(byte)
        end

        value = value + byte

        if last and value < 4294967296 then
            -- success
            return value, size
        end
    end
    -- returns nil if we didn't find a last byte, or value is too big
end


----------------------------------------
-- returns Lua number of a 32-bit signed varint
function varint:decodeSigned32(buff, offset, length)
    local value, size = self:decode32(buff, offset, length)

    if not value then return end

    if value > 2147483647 then
        -- convert two's complement = subtract (2^31 + 1)
        return value - 2147483649, size
    end

    return value, size
end


local max_int32 = 2147483647
local min_int32 = -2147483648


function varint:decodeSigned32As64(buff, offset, length)
    local value, size = self:decodeSigned64(buff, offset, length)

    if not value then return end

    value = value:tonumber()
    if value >= min_int32 and value <= max_int32 then
        return value, size
    else
        -- TODO: expert info number too big?
    end
end


local allOnes32 = bit.bnot(0)

----------------------------------------
-- returns Lua number of the zig-zag encoded value
function varint:decodeZigZag32(buff, offset, length)
    local value, size = self:decode32(buff, offset, length)

    if not value then return end

    -- odd numbers are negative, even are positive
    if bit.band(value, 1) == 0 then
        -- positive
        --dassert(bit.rshift(value, 1) == value / 2, "Programming error: decodeZigZag32() rshift != div")
        return bit.rshift(value, 1), size
    end

    return bit.bxor(bit.rshift(value, 1), allOnes32), size
end


----------------------------------------
-- gets a 64-bit unsigned varint, as a UInt64 object
function varint:decode64(buff, offset, length)
    local bytes = getBytes64(buff, offset, length)

    local value = UInt64.new()

    for size, byte in ipairs(bytes) do
        -- it's the last one if MSB is 0
        local last = byte < 128

        -- clear MSB, if it's even set
        byte = byte % 128

        if last and size == 10 and byte > 1 then
            -- prevent value too big/overflow
            return nil
        end

        -- convert to UInt64
        byte = UInt64.new(byte)

        -- left shift by number of bytes * 7 bits per byte
        byte = byte:lshift((size - 1) * 7)
        value = value + byte

        if last then
            -- success
            return value, size
        end
    end
    -- returns nil if we didn't find a last byte
end


----------------------------------------
-- gets a 64-bit varint (signed), as a Int64 object
function varint:decodeSigned64(buff, offset, length)
    local value, size = self:decode64(buff, offset, length)

    if not value then return end

    -- if value > msb64 then
    --     -- convert two's complement = subtract (2^63 + 1)
    --     return value - msb64, size
    -- end

    return Int64.new(value), size
end


-- for some reason wireshark isn't comparing UInt64 to native Lua numbers
-- right, so we use this UInt64 to compare to a 0
local equalZero64 = UInt64.new(0)


----------------------------------------
-- returns Int64 object of the zig-zag encoded value
function varint:decodeZigZag64(buff, offset, length)
    local value, size = self:decode64(buff, offset, length)

    if not value then return end

    -- odd numbers are negative, even are positive
    if equalZero64 == value:band(1) then
        -- positive
        return Int64.new(value:rshift(1)), size
    end

    local tmp = value:rshift(1)

    -- lower and higher are Lua numbers
    local lower, higher = tmp:lower(), tmp:higher()

    lower = bit.bxor(lower, allOnes32)
    lower = unsign(lower)

    higher = bit.bxor(higher, allOnes32)
    higher = unsign(higher)

    return Int64.new(lower, higher), size
end


return varint
