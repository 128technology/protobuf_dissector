--
-- Copyright (c) 2015 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
--
-- This code is licensed under the MIT license.

local svrcrypto = require("svrcrypto")

local function from_hex(value)
    return (value:gsub("..", function(byte)
        return string.char(tonumber(byte, 16))
    end))
end

local function to_hex(value)
    return (value:gsub(".", function(byte)
        return string.format("%02x", string.byte(byte))
    end))
end

local cbc_plaintext = from_hex("6bc1bee22e409f96e93d7e117393172a")
local cbc_ciphertext = from_hex("7649abac8119b246cee98e9b12e9197d")
local cbc_key = from_hex("2b7e151628aed2a6abf7158809cf4f3c")
local cbc_iv = from_hex("000102030405060708090a0b0c0d0e0f")
assert(to_hex(svrcrypto.decrypt_cbc(cbc_key, cbc_iv, cbc_ciphertext)) ==
    to_hex(cbc_plaintext))

local cbc256_key = from_hex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
local cbc256_ciphertext = from_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
assert(to_hex(svrcrypto.decrypt_cbc(cbc256_key, cbc_iv, cbc256_ciphertext)) ==
    to_hex(cbc_plaintext))

local gcm_plaintext = string.rep("\0", 16)
local gcm_ciphertext = from_hex("0388dace60b6a392f328c2b971b2fe78")
local gcm_key = string.rep("\0", 16)
local gcm_nonce = string.rep("\0", 12)
local gcm_tag = from_hex("ab6e47d42cec13bdf53a67b21257bddf")
assert(svrcrypto.decrypt_gcm(gcm_key, gcm_nonce, gcm_ciphertext, gcm_tag) ==
    gcm_plaintext)

local gcm256_key = string.rep("\0", 32)
local gcm256_ciphertext = from_hex("cea7403d4d606b6e074ec5d3baf39d18")
local gcm256_tag = from_hex("d0d1c8a799996bf0265b98b5d48ab919")
assert(svrcrypto.decrypt_gcm(
    gcm256_key, gcm_nonce, gcm256_ciphertext, gcm256_tag
) == gcm_plaintext)

local result, err = svrcrypto.decrypt_gcm(
    gcm_key, gcm_nonce, gcm_ciphertext, string.rep("\0", 16))
assert(result == nil and err == "AES-GCM authentication failed")
