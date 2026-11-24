----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
--
-- This code is licensed under the MIT license.
--
------------------------------------------

if not _G["protbuf_dissector"] then return end
if _G["ssr_bfd_proto"] then return end

local metadata_dissector = Dissector.get("pb.bfd.metadata")
if not metadata_dissector then
    error("SSR BFD dissector requires protobuf.lua to load files/bfd.proto first")
end

local ssr_bfd = Proto("ssr_bfd", "SSR BFD Metadata")
local fields = {
    version = ProtoField.uint8("ssr_bfd.version", "Version", base.DEC),
    length = ProtoField.uint8("ssr_bfd.length", "BFD Length", base.DEC),
    metadata_length = ProtoField.uint32("ssr_bfd.metadata_length", "Metadata Length", base.DEC),
    trailing = ProtoField.bytes("ssr_bfd.trailing", "Trailing Data", base.SPACE),
}
local experts = {
    invalid_header = ProtoExpert.new(
        "ssr_bfd.invalid_header",
        "Invalid SSR BFD header",
        expert.group.PROTOCOL,
        expert.severity.ERROR
    ),
    length_mismatch = ProtoExpert.new(
        "ssr_bfd.length_mismatch",
        "BFD length does not match UDP payload; retried with full payload",
        expert.group.PROTOCOL,
        expert.severity.WARN
    ),
    saturated_length = ProtoExpert.new(
        "ssr_bfd.saturated_length",
        "BFD length byte saturated at 255",
        expert.group.PROTOCOL,
        expert.severity.NOTE
    ),
    auth_present = ProtoExpert.new(
        "ssr_bfd.auth_present",
        "BFD authentication is present; SSR metadata decoding still starts at byte 24",
        expert.group.PROTOCOL,
        expert.severity.NOTE
    ),
    metadata_error = ProtoExpert.new(
        "ssr_bfd.metadata_error",
        "Unable to decode BFD protobuf metadata",
        expert.group.PROTOCOL,
        expert.severity.ERROR
    ),
}

ssr_bfd.fields = fields
ssr_bfd.experts = experts

local function portIsSelected(pinfo, port)
    return pinfo.src_port == port or pinfo.dst_port == port
end

local function isBfdPacket(tvb, pinfo, port)
    if tvb:len() < 24 or not portIsSelected(pinfo, port) then
        return false
    end
    local version = math.floor(tvb(0, 1):uint() / 32)
    return version == 1 and tvb(3, 1):uint() >= 24
end

local function decodeMetadata(metadata_tvb, pinfo, tree)
    metadata_dissector:call(metadata_tvb, pinfo, tree)
end

local function readVarint(data, offset)
    local value = 0
    local multiplier = 1
    for _ = 1, 10 do
        if offset > #data then
            return nil
        end
        local byte = data:byte(offset)
        offset = offset + 1
        value = value + (byte % 128) * multiplier
        if byte < 128 then
            return value, offset
        end
        multiplier = multiplier * 128
    end
end

local function readFields(data)
    local fields = {}
    local offset = 1
    while offset <= #data do
        local key
        key, offset = readVarint(data, offset)
        if not key then
            return nil
        end

        local tag = math.floor(key / 8)
        local wire_type = key % 8
        local value
        if wire_type == 0 then
            value, offset = readVarint(data, offset)
            if value == nil then
                return nil
            end
        elseif wire_type == 1 then
            if offset + 7 > #data then return nil end
            value = data:sub(offset, offset + 7)
            offset = offset + 8
        elseif wire_type == 2 then
            local length
            length, offset = readVarint(data, offset)
            if length == nil or length > #data - offset + 1 then
                return nil
            end
            value = data:sub(offset, offset + length - 1)
            offset = offset + length
        elseif wire_type == 5 then
            if offset + 3 > #data then return nil end
            value = data:sub(offset, offset + 3)
            offset = offset + 4
        else
            return nil
        end
        fields[#fields + 1] = {tag = tag, wire_type = wire_type, value = value}
    end
    return fields
end

local function firstField(fields, tag)
    for _, field in ipairs(fields or {}) do
        if field.tag == tag then
            return field.value
        end
    end
end

local keyTypeNames = {
    [0] = "CERT",
    [1] = "PUB_DH_KEY",
    [2] = "SALT",
    [3] = "META_DATA_KEY",
    [4] = "ML_KEM_KEY",
}

local function peerKey(pinfo)
    local source = tostring(pinfo.src)
    local destination = tostring(pinfo.dst)
    if source < destination then
        return source .. "|" .. destination
    end
    return destination .. "|" .. source
end

local keyIndicesByPeer = _G["ssr_bfd_metadata_key_indices"] or {}
_G["ssr_bfd_metadata_key_indices"] = keyIndicesByPeer

local function metadataSummary(data, pinfo)
    local summary = {}
    local metadata_fields = readFields(data)
    if not metadata_fields then
        return "Metadata"
    end

    local session_data = firstField(metadata_fields, 1)
    if session_data then
        local peer_name = firstField(readFields(session_data), 3)
        if peer_name and #peer_name > 0 then
            summary[#summary + 1] = "peer=" .. peer_name
        end
    end

    local node_info = firstField(metadata_fields, 3)
    if node_info then
        local node_id = firstField(readFields(node_info), 1)
        if node_id then
            summary[#summary + 1] = "node=" .. tostring(node_id)
        end
    end

    local echo = firstField(metadata_fields, 2)
    if echo then
        local echo_fields = readFields(echo)
        if firstField(echo_fields, 1) then
            summary[#summary + 1] = "EchoRequest"
        elseif firstField(echo_fields, 2) then
            summary[#summary + 1] = "EchoResponse"
        end
        if firstField(echo_fields, 3) == 1 then
            summary[#summary + 1] = "MTU discovery"
        end
        if firstField(echo_fields, 4) == 1 then
            summary[#summary + 1] = "Peer traceroute"
        end
    end

    local key_data = firstField(metadata_fields, 4)
    if key_data then
        local key_fields = readFields(key_data)
        local key_type = firstField(key_fields, 1)
        local ack = firstField(key_fields, 6)
        local metadata_key_index = firstField(key_fields, 5)
        local type_name = keyTypeNames[key_type]
        local key_info = {type_name or (ack == 1 and "ACK-only" or "UnknownKey")}
        if ack == 1 then
            if type_name then
                key_info[#key_info + 1] = "ACK"
            end
        end
        if metadata_key_index then
            key_info[#key_info + 1] = "index=" .. tostring(metadata_key_index)
            if key_type == 3 and ack ~= 1 then
                keyIndicesByPeer[peerKey(pinfo)] = metadata_key_index
            end
        end
        summary[#summary + 1] = table.concat(key_info, " ")
    end

    if #summary == 0 then
        return "Metadata"
    end
    return table.concat(summary, " ")
end

function ssr_bfd.dissector(tvb, pinfo, tree)
    if tvb:len() < 24 then
        return 0
    end

    local version = math.floor(tvb(0, 1):uint() / 32)
    if version ~= 1 then
        return 0
    end

    local root = tree:add(ssr_bfd, tvb(), "SSR BFD Metadata")
    root:add(fields.version, tvb(0, 1), version)
    local bfd_length = tvb(3, 1):uint()
    root:add(fields.length, tvb(3, 1))

    local bfd_dissector = Dissector.get("bfd")
    if bfd_dissector then
        local bfd_header_length = 24
        local has_auth = tvb(1, 1):uint() % 8 >= 4
        if has_auth then
            root:add_proto_expert_info(experts.auth_present)
            if tvb:len() >= 26 then
                local auth_length = tvb(25, 1):uint()
                if auth_length >= 2 and auth_length <= tvb:len() - 24 and
                   auth_length <= math.max(0, bfd_length - 24) then
                    bfd_header_length = 24 + auth_length
                else
                    root:add_proto_expert_info(experts.invalid_header)
                end
            else
                root:add_proto_expert_info(experts.invalid_header)
            end
        end
        bfd_dissector:call(tvb(0, bfd_header_length):tvb(), pinfo, root)
    end

    local payload_length = tvb:len() - 24
    if bfd_length < 24 then
        root:add_proto_expert_info(experts.invalid_header)
        pinfo.cols.protocol:set("SSR BFD")
        return tvb:len()
    end

    local declared_length = math.min(payload_length, bfd_length - 24)
    if payload_length == 0 then
        pinfo.cols.protocol:set("SSR BFD")
        return tvb:len()
    end

    if bfd_length == 255 and payload_length > 231 then
        root:add_proto_expert_info(experts.saturated_length)
    end

    local metadata_item = root:add(fields.metadata_length, payload_length)
    local metadata_tree = root:add(tvb(24, payload_length), "Protobuf Metadata")
    local decode_length = declared_length
    if decode_length == 0 then
        decode_length = payload_length
        metadata_item:add_proto_expert_info(experts.length_mismatch)
    end
    local metadata_tvb = tvb(24, decode_length):tvb()
    local ok, err = pcall(decodeMetadata, metadata_tvb, pinfo, metadata_tree)

    if not ok and decode_length < payload_length then
        metadata_item:add_proto_expert_info(experts.length_mismatch)
        metadata_tvb = tvb(24, payload_length):tvb()
        ok, err = pcall(decodeMetadata, metadata_tvb, pinfo, metadata_tree)
    end

    if not ok then
        metadata_item:add_proto_expert_info(experts.metadata_error, tostring(err))
    elseif decode_length < payload_length then
        local trailing_offset = 24 + decode_length
        root:add(fields.trailing, tvb(trailing_offset, payload_length - decode_length))
    end

    pinfo.cols.protocol:set("SSR BFD")
    pinfo.cols.info:append(" [" .. metadataSummary(tvb(24, payload_length):raw(), pinfo) .. "]")
    return tvb:len()
end

local current_port = 1280
ssr_bfd.prefs.udp_port = Pref.uint(
    "UDP port",
    current_port,
    "UDP port used by SSR BFD control packets",
    65535
)

ssr_bfd.prefs_changed = function()
    local new_port = ssr_bfd.prefs.udp_port
    if new_port ~= current_port then
        local udp_ports = DissectorTable.get("udp.port")
        udp_ports:remove(current_port, ssr_bfd)
        current_port = new_port
        if current_port ~= 0 then
            udp_ports:add(current_port, ssr_bfd)
        end
    end
end

if current_port ~= 0 then
    DissectorTable.get("udp.port"):add(current_port, ssr_bfd)
end

ssr_bfd:register_heuristic("udp", function(tvb, pinfo, tree)
    if not isBfdPacket(tvb, pinfo, ssr_bfd.prefs.udp_port) then
        return false
    end
    ssr_bfd.dissector(tvb, pinfo, tree)
    return true
end)

_G["ssr_bfd_proto"] = ssr_bfd
return ssr_bfd
