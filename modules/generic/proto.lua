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


local Settings            = require "settings"
local dprint              = Settings.dprint

local Prefs               = require "prefs"
local Framing             = require "generic.tcp_framing"
local Compiler            = require "compiler"
local PacketDecoder       = require "generic.packet"
local Decoder            = require "back_end.decoder"
local GenericDecoder     = require "generic.decoder"
local Fixed32Decoder     = require "generic.fixed32"
local Fixed64Decoder     = require "generic.fixed64"
local VarintDecoder      = require "generic.varint"
local GroupDecoder       = require "generic.group"
local BytesDecoder       = require "generic.bytes"
local GenericProtoFields = require "generic.proto_fields"
local GenericExperts     = require "generic.experts"


--------------------------------------------------------------------------------
-- our module table that we return to the caller of this script
local GenericProto = {}


GenericProto.proto = Proto.new("protobuf_lua", "Google Protobuf Format (Lua)")

local pfields = GenericProtoFields:getFields()

-- register the ProtoFields and Experts
GenericProto.proto.fields = pfields
GenericProto.proto.experts = GenericExperts:getFields()


--------------------------------------------------------------------------------
-- "SSR protobuf directory" preference: an additional, separate directory of
-- '.proto' files (e.g. SSR-specific protobuf protocols) that should be
-- compiled and made available as dissectors, on top of the normal
-- Settings.proto_dirs/proto_files. This is attached only to the generic
-- fallback Proto (not every compiled message Proto), since it's a single,
-- global setting, not a per-message one.
--
-- It's read via the "prefs_changed" hook (the only point at which a Pref's
-- real/overridden value - whether set via the GUI, a preferences file, or a
-- "-o" command-line override - is guaranteed to be visible), and each
-- distinct non-empty directory value is compiled at most once (tracked via
-- 'compiled_extra_dirs'), since re-compiling the same directory again would
-- attempt to create duplicate Proto objects and error out.
--
-- For convenience in scripted/automated test setups (where setting a Lua
-- preference via "-o" before the first packet is dissected is sufficient,
-- but an environment variable can be simpler to arrange), the
-- "SSR_PROTOBUF_DIR" environment variable is used as the preference's
-- default value if set.
local compiled_extra_dirs = {}

local dir_separator = package.config:sub(1, 1)

local function compileSsrProtobufDir(dir)
    if not dir or dir == "" or compiled_extra_dirs[dir] then
        return
    end

    compiled_extra_dirs[dir] = true

    if not Dir.exists(dir) then
        dprint("Protobuf: SSR protobuf directory does not exist:", dir)
        return
    end

    local files = {}
    for filename in Dir.open(dir, ".proto") do
        files[#files + 1] = dir .. dir_separator .. filename
    end

    if #files == 0 then
        dprint("Protobuf: SSR protobuf directory has no '.proto' files:", dir)
        return
    end

    -- best-effort: don't let a bad/unrelated directory's proto files break
    -- the dissectors that are already working
    local ok, err = pcall(function() Compiler:compile(files) end)
    if not ok then
        dprint("Protobuf: failed to compile SSR protobuf directory '", dir, "':", err)
    end
end

-- create the Preferences; the SSR protobuf directory handling is chained
-- onto the Proto's "prefs_changed" from within Prefs:create(), since
-- Proto.prefs_changed is write-only and so can't be read back afterward
-- to chain it here instead
Prefs:create(GenericProto.proto, function()
    compileSsrProtobufDir(GenericProto.proto.prefs.ssr_protobuf_dir)
end)

GenericProto.proto.prefs.ssr_protobuf_dir = Pref.string(
    "SSR protobuf directory",
    os.getenv("SSR_PROTOBUF_DIR") or "",
    "An additional directory of '.proto' files to compile and expose as " ..
    "dissectors (e.g. for SSR-specific protobuf-based protocols). Each " ..
    "distinct directory is only compiled once.")


GenericDecoder:register("FIXED32", Fixed32Decoder.new(pfields.FIXED32))
GenericDecoder:register("FIXED64", Fixed64Decoder.new(pfields.FIXED64))
GenericDecoder:register("VARINT", VarintDecoder.new(pfields.VARINT))
GenericDecoder:register("START_GROUP", GroupDecoder.new(pfields.GROUP))
GenericDecoder:register("LENGTH_DELIMITED", BytesDecoder.new(pfields.LENGTH_BYTES))




local packet_decoder = PacketDecoder.new(GenericProto.proto)

local function dissect_message(tvbuf, pktinfo, root)
    return Decoder.new(tvbuf, pktinfo, root):decode(packet_decoder)
end

GenericProto.proto.dissector = Framing.wrap(GenericProto.proto, dissect_message)


DissectorTable.get("udp.port"):add(0, GenericProto.proto)
DissectorTable.get("tcp.port"):add(0, GenericProto.proto)


return GenericProto
