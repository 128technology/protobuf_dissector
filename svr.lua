----------------------------------------
--
-- Copyright (c) 2015, 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
--
-- This code is licensed under the MIT license.
--
------------------------------------------

if _G["svr_proto"] then return end

local svr = Proto("svr", "Secure Vector Routing Metadata")
local type_names = {
    [1] = "Fragment",
    [2] = "Forward Session Key IPv4",
    [3] = "Forward Session Key IPv6",
    [4] = "Reverse Session Key IPv4",
    [5] = "Reverse Session Key IPv6",
    [6] = "Session ID",
    [7] = "Source Tenant Name",
    [8] = "Ingress GIID",
    [9] = "Egress GIID",
    [10] = "Service Name",
    [11] = "Session Encrypted",
    [12] = "TCP SYN Packet",
    [13] = "Number Of Sessions",
    [14] = "Source Peer Name",
    [15] = "Source Peer Security Name",
    [16] = "Security Identifier",
    [17] = "Destination Peer Name",
    [18] = "Disable Forward Metadata",
    [19] = "Source Peer Path Identifier",
    [20] = "Source Address IPv4",
    [21] = "Source Address IPv6",
    [22] = "Source Application Queue",
    [23] = "Selective Acknowledgement",
    [24] = "Forced Drop",
    [25] = "Source NAT IPv4",
    [26] = "Path Metrics",
    [27] = "Source L2 Info",
    [28] = "Modify Request",
    [29] = "Domain Name",
    [30] = "Parsed Payload Type",
    [31] = "Session Capture",
    [32] = "EoSVR Encapsulation",
    [33] = "Session Capture Tag",
    [34] = "DSCP Steering",
    [35] = "Classified App Name",
    [36] = "Classified App Type",
    [37] = "Classified App Category",
    [38] = "URI",
    [39] = "Path Metrics Marking Counts",
    [40] = "Path Metrics Marking Ack",
    [41] = "Classified App Subcategory",
    [42] = "Remaining Session Timeout",
    [43] = "Update TTL",
    [44] = "DSCP Restore",
    [45] = "Waypoint Ports",
    [46] = "Session Health Check",
    [47] = "TCP Stitching",
    [48] = "Path Metrics Sender Key",
    [49] = "SVR2 Indices",
    [50] = "Payload Key",
    [51] = "FIB Lookup Key IPv4",
    [52] = "FIB Lookup Key IPv6",
}
local fields = {
    cookie = ProtoField.bytes("svr.cookie", "Cookie", base.SPACE),
    version = ProtoField.uint8("svr.version", "Version", base.DEC),
    header_length = ProtoField.uint16("svr.hdr_len", "Header Length", base.DEC),
    payload_length = ProtoField.uint16("svr.payload_len", "Payload Metadata Length", base.DEC),
    tlv_type = ProtoField.uint16("svr.tlv.type", "TLV Type", base.DEC, type_names),
    tlv_length = ProtoField.uint16("svr.tlv.len", "TLV Length", base.DEC),
    tlv_value = ProtoField.bytes("svr.tlv.value", "TLV Value", base.SPACE),
    tlv_text = ProtoField.string("svr.tlv.text", "Decoded Value"),
    encrypted_metadata = ProtoField.bytes("svr.encrypted_metadata", "Encrypted Payload Metadata", base.SPACE),
    decrypted_metadata = ProtoField.bytes("svr.decrypted_metadata", "Decrypted Payload Metadata", base.SPACE),
    inner_payload = ProtoField.bytes("svr.inner_payload", "Inner Payload", base.SPACE),
    encrypted_payload = ProtoField.bytes("svr.encrypted_payload", "Encrypted Inner Payload", base.SPACE),
    opaque_payload = ProtoField.bytes("svr.opaque_payload", "Inner Payload (Encryption Unknown)", base.SPACE),
    hmac = ProtoField.bytes("svr.hmac", "HMAC", base.SPACE),
    security_identifier = ProtoField.uint32("svr.security_identifier", "Security Identifier", base.DEC),
    session_id = ProtoField.bytes("svr.session_id", "Session ID", base.SPACE),
    eskm_rekey_index = ProtoField.uint8("svr.eskm.rekey_index", "ESKM Rekey Index", base.DEC),
    svr2_payload_index = ProtoField.uint8("svr.svr2.payload_index", "SVR2 Payload Index", base.DEC),
    cached_rekey_index = ProtoField.uint8(
        "svr.session_cache.rekey_index", "Cached SVR2 Rekey Index", base.DEC
    ),
    cached_payload_index = ProtoField.uint8(
        "svr.session_cache.payload_index", "Cached SVR2 Payload Index", base.DEC
    ),
    eskm_key_index = ProtoField.uint32("svr.eskm_key_index", "ESKM Metadata Key Index", base.DEC),
    forced_drop_reason = ProtoField.uint8("svr.forced_drop.reason", "Forced Drop Reason", base.DEC),
    waypoint_source_port = ProtoField.uint16("svr.waypoint.source_port", "Waypoint Source Port", base.DEC),
    waypoint_destination_port = ProtoField.uint16("svr.waypoint.destination_port", "Waypoint Destination Port", base.DEC),
    source_ipv4 = ProtoField.ipv4("svr.source_ipv4", "Source Address"),
    source_ipv6 = ProtoField.ipv6("svr.source_ipv6", "Source Address"),
    path_marking_tx = ProtoField.uint16("svr.path_metrics.tx_count", "Path Metrics Transmit Count", base.DEC),
    path_marking_rx = ProtoField.uint16("svr.path_metrics.rx_count", "Path Metrics Receive Count", base.DEC),
    path_tx_color = ProtoField.uint8("svr.path_metrics.tx_color", "Transmit Color", base.DEC),
    path_tx_time = ProtoField.uint32("svr.path_metrics.tx_time", "Transmit Time Value", base.DEC),
    path_rx_color = ProtoField.uint8("svr.path_metrics.rx_color", "Received Color", base.DEC),
    path_rx_time = ProtoField.uint32("svr.path_metrics.rx_time", "Received Time Value", base.DEC),
    path_drop = ProtoField.uint8("svr.path_metrics.drop", "Path Metrics Drop Flag", base.DEC),
    path_previous_rx_count = ProtoField.uint16(
        "svr.path_metrics.previous_rx_count", "Previous Receive Color Count", base.DEC
    ),
    path_index = ProtoField.uint32("svr.path_metrics.path_index", "Path Index", base.DEC),
    path_priority = ProtoField.uint8("svr.path_metrics.priority", "Path Priority", base.DEC),
    fragment_extended_id = ProtoField.uint32("svr.fragment.extended_id", "Fragment Extended ID", base.DEC),
    fragment_original_id = ProtoField.uint16("svr.fragment.original_id", "Fragment Original ID", base.DEC),
    fragment_flags = ProtoField.uint16("svr.fragment.flags", "Fragment Flags", base.HEX),
    fragment_offset = ProtoField.uint16("svr.fragment.offset", "Fragment Offset", base.DEC),
    fragment_largest = ProtoField.uint16("svr.fragment.largest", "Largest Seen Fragment", base.DEC),
    session_source_ipv4 = ProtoField.ipv4("svr.session_key.source_ipv4", "Session Key Source Address"),
    session_destination_ipv4 = ProtoField.ipv4("svr.session_key.destination_ipv4", "Session Key Destination Address"),
    session_source_ipv6 = ProtoField.ipv6("svr.session_key.source_ipv6", "Session Key Source Address"),
    session_destination_ipv6 = ProtoField.ipv6("svr.session_key.destination_ipv6", "Session Key Destination Address"),
    session_source_port = ProtoField.uint16("svr.session_key.source_port", "Session Key Source Port", base.DEC),
    session_destination_port = ProtoField.uint16("svr.session_key.destination_port", "Session Key Destination Port", base.DEC),
    session_protocol = ProtoField.uint8("svr.session_key.protocol", "Session Key Protocol", base.DEC),
    session_capture = ProtoField.uint64("svr.session_capture", "Session Capture Packet Count", base.DEC),
    number_of_sessions = ProtoField.uint64("svr.number_of_sessions", "Number Of Sessions", base.DEC),
    ingress_giid = ProtoField.uint32("svr.ingress_giid", "Ingress GIID", base.DEC),
    egress_giid = ProtoField.uint32("svr.egress_giid", "Egress GIID", base.DEC),
    sack_base_sequence = ProtoField.uint32("svr.sack.base_sequence", "SACK Base Sequence", base.DEC),
    sack_left_edge = ProtoField.uint32("svr.sack.left_edge", "SACK Left Edge", base.DEC),
    sack_right_edge = ProtoField.uint32("svr.sack.right_edge", "SACK Right Edge", base.DEC),
    source_l2_mac = ProtoField.ether("svr.source_l2.source", "Source MAC Address"),
    destination_l2_mac = ProtoField.ether("svr.source_l2.destination", "Destination MAC Address"),
    source_nat_ipv4 = ProtoField.ipv4("svr.source_nat.ipv4", "Source NAT Address"),
    source_nat_port = ProtoField.uint16("svr.source_nat.port", "Source NAT Port", base.DEC),
    dscp = ProtoField.uint8("svr.dscp", "DSCP", base.DEC),
    remaining_timeout = ProtoField.uint32("svr.remaining_timeout", "Remaining Session Timeout", base.DEC),
    fib_destination_ipv4 = ProtoField.ipv4("svr.fib.destination_ipv4", "FIB Destination Address"),
    fib_destination_ipv6 = ProtoField.ipv6("svr.fib.destination_ipv6", "FIB Destination Address"),
    fib_destination_port = ProtoField.uint16("svr.fib.destination_port", "FIB Destination Port", base.DEC),
    fib_protocol = ProtoField.uint8("svr.fib.protocol", "FIB Protocol", base.DEC),
}
local allowed_hmac_lengths = {[16] = true, [20] = true, [32] = true, [48] = true, [64] = true}
local sessions = {}
local session_order = {}
local session_order_head = 1
local session_generation = 0
local max_cached_flows = 8192
local experts
local key_preferences
local key_preference_errors = 0
local key_preference_text

local plugin_source = debug.getinfo(1, "S").source
if plugin_source:sub(1, 1) == "@" then
    local plugin_path = plugin_source:sub(2)
    local plugin_dir = plugin_path:match("^(.*)[/\\][^/\\]+$")
    if plugin_dir then
        local native_path = plugin_dir .. package.config:sub(1, 1) ..
            "native" .. package.config:sub(1, 1) .. "?.so"
        if not package.cpath:find(native_path, 1, true) then
            package.cpath = native_path .. ";" .. package.cpath
        end
    end
end

local crypto_loaded, crypto = pcall(require, "svrcrypto")
local crypto_load_error
if not crypto_loaded then
    crypto_load_error = tostring(crypto)
    crypto = nil
end

local function getMode(value, preference_name, root)
    if value == "auto" or value == "always" or value == "never" then
        return value
    end
    root:add_proto_expert_info(experts.invalid_preference, "Use auto, always, or never for " .. preference_name)
    return "auto"
end

local function peerKey(pinfo)
    local source = tostring(pinfo.src)
    local destination = tostring(pinfo.dst)
    if source < destination then
        return source .. "|" .. destination
    end
    return destination .. "|" .. source
end

local function addKeyCorrelation(root, pinfo, context)
    local key_indices = _G["ssr_bfd_metadata_key_indices"]
    local eskm_index = key_indices and key_indices[peerKey(pinfo)]
    if eskm_index == nil then
        return nil
    end
    root:add(fields.eskm_key_index, eskm_index):set_generated()
    if context.rekey_index ~= nil then
        return string.format(" ESKM key=%d SVR key=%d", eskm_index, context.rekey_index)
    end
    return string.format(" ESKM key=%d", eskm_index)
end

local function flowKey(pinfo, reverse)
    local source = tostring(pinfo.src)
    local destination = tostring(pinfo.dst)
    local source_port = tostring(pinfo.src_port)
    local destination_port = tostring(pinfo.dst_port)
    if reverse then
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    end
    return table.concat({
        tostring(pinfo.port_type),
        source,
        source_port,
        destination,
        destination_port,
    }, "|")
end

local function rememberFlow(key, context)
    local cached = sessions[key]
    if cached then
        for _, name in ipairs({
            "protocol",
            "source_port",
            "destination_port",
            "session_id",
            "security_identifier",
            "rekey_index",
            "payload_index",
            "session_encrypted",
            "metadata_encrypted",
            "waypoint",
        }) do
            if context[name] ~= nil then
                cached[name] = context[name]
            end
        end
        return
    end

    session_generation = session_generation + 1
    context.generation = session_generation
    sessions[key] = context
    session_order[#session_order + 1] = {key = key, generation = session_generation}

    while #session_order - session_order_head + 1 > max_cached_flows do
        local oldest = session_order[session_order_head]
        session_order[session_order_head] = false
        session_order_head = session_order_head + 1
        local current = sessions[oldest.key]
        if current and current.generation == oldest.generation then
            sessions[oldest.key] = nil
        end
    end
    if session_order_head > 4096 then
        local compacted = {}
        for index = session_order_head, #session_order do
            compacted[#compacted + 1] = session_order[index]
        end
        session_order = compacted
        session_order_head = 1
    end
end

local function cacheSession(pinfo, context)
    if not pinfo.src_port or not pinfo.dst_port then
        return
    end
    rememberFlow(flowKey(pinfo), context)
    local reverse = {
        protocol = context.protocol,
        source_port = context.destination_port,
        destination_port = context.source_port,
        session_id = context.session_id,
        security_identifier = context.security_identifier,
        rekey_index = context.rekey_index,
        payload_index = context.payload_index,
        session_encrypted = context.session_encrypted,
        metadata_encrypted = context.metadata_encrypted,
        waypoint = context.waypoint,
    }
    rememberFlow(flowKey(pinfo, true), reverse)
end

experts = {
    invalid_header = ProtoExpert.new(
        "svr.invalid_header", "Invalid SVR header", expert.group.PROTOCOL, expert.severity.ERROR
    ),
    invalid_length = ProtoExpert.new(
        "svr.invalid_length", "SVR length exceeds packet bounds", expert.group.MALFORMED, expert.severity.ERROR
    ),
    invalid_preference = ProtoExpert.new(
        "svr.invalid_preference", "Invalid SVR preference", expert.group.PROTOCOL, expert.severity.WARN
    ),
    malformed_tlv = ProtoExpert.new(
        "svr.malformed_tlv", "Malformed SVR TLV", expert.group.MALFORMED, expert.severity.ERROR
    ),
    unknown_type = ProtoExpert.new(
        "svr.unknown_type", "Unknown SVR TLV type", expert.group.PROTOCOL, expert.severity.WARN
    ),
    wrong_section = ProtoExpert.new(
        "svr.wrong_section", "SVR TLV is in unexpected section", expert.group.PROTOCOL, expert.severity.NOTE
    ),
    opaque_encryption = ProtoExpert.new(
        "svr.opaque_encryption", "SVR encryption state is unknown or data remains opaque",
        expert.group.PROTOCOL, expert.severity.NOTE
    ),
    decryption_failed = ProtoExpert.new(
        "svr.decryption_failed", "SVR decryption failed",
        expert.group.PROTOCOL, expert.severity.WARN
    ),
    cbc_unverified = ProtoExpert.new(
        "svr.cbc_unverified", "AES-CBC plaintext is unauthenticated",
        expert.group.SECURITY, expert.severity.NOTE
    ),
}

svr.fields = fields
svr.experts = experts

local cookie = "\x4c\x48\xdb\xc6\xdd\xf6\x67\x0c"
local header_size = 12

local header_types = {
    [1] = true, [16] = true, [18] = true, [20] = true, [21] = true,
    [23] = true, [24] = true, [26] = true, [28] = true, [39] = true,
    [40] = true, [45] = true, [46] = true, [48] = true, [49] = true,
}

local fixed_lengths = {
    [1] = 10, [2] = 13, [3] = 37, [4] = 13, [5] = 37,
    [6] = 16, [8] = 4, [9] = 4, [11] = 0, [12] = 0,
    [13] = 8, [16] = 4, [18] = 0, [20] = 4, [21] = 16,
    [24] = 1, [25] = 6, [26] = 10, [27] = 12, [28] = 2,
    [31] = 8, [32] = 0, [34] = 1, [39] = 4, [40] = 0,
    [42] = 4, [43] = 0, [44] = 1, [45] = 4, [46] = 1,
    [47] = 0, [48] = 5, [49] = 2, [51] = 7, [52] = 19,
}

local forced_drop_names = {
    [0] = "Unknown",
    [1] = "Keep Alive",
    [2] = "Enable Metadata",
    [3] = "Disable Metadata",
    [4] = "Flow Move",
    [5] = "Path Metrics",
    [6] = "Delete Session",
    [7] = "Divert ICMP Error",
    [8] = "Session Health Check",
}

local function valueRange(tvb, offset, length)
    return tvb(offset, length)
end

local function decodeTlv(tvb, tree, offset, section, summary, context)
    local tlv_type = tvb(offset, 2):uint()
    local length = tvb(offset + 2, 2):uint()
    local value_offset = offset + 4
    local value_range = valueRange(tvb, value_offset, length)
    local name = type_names[tlv_type]
    local item = tree:add(fields.tlv_type, tvb(offset, 2))
    item:add(fields.tlv_length, tvb(offset + 2, 2))
    item:add(fields.tlv_value, value_range)

    if not name then
        item:add_proto_expert_info(experts.unknown_type)
        return value_offset + length
    end
    if (section == "header") ~= (header_types[tlv_type] == true) then
        item:add_proto_expert_info(experts.wrong_section)
    end

    local expected = fixed_lengths[tlv_type]
    if expected ~= nil and length ~= expected then
        item:add_proto_expert_info(experts.malformed_tlv, "Unexpected TLV length")
        context.malformed = true
        return value_offset + length
    end

    local decoded
    if tlv_type == 16 then
        local value = value_range:uint()
        item:add(fields.security_identifier, value_range, value)
        context.security_identifier = value
        decoded = tostring(value)
    elseif tlv_type == 6 then
        item:add(fields.session_id, value_range)
        context.session_id = value_range:raw()
        decoded = "present"
    elseif tlv_type == 8 or tlv_type == 9 then
        local giid = value_range:uint()
        item:add(tlv_type == 8 and fields.ingress_giid or fields.egress_giid, value_range, giid)
        decoded = tostring(giid)
    elseif tlv_type == 49 then
        local rekey_index = value_range(0, 1):uint()
        local payload_index = value_range(1, 1):uint()
        item:add(fields.eskm_rekey_index, value_range(0, 1))
        item:add(fields.svr2_payload_index, value_range(1, 1))
        context.rekey_index = rekey_index
        context.payload_index = payload_index
        decoded = string.format("rekey=%d payload=%d", rekey_index, payload_index)
    elseif tlv_type == 11 then
        context.session_encrypted = true
        decoded = "yes"
    elseif tlv_type == 24 then
        local reason = value_range:uint()
        item:add(fields.forced_drop_reason, value_range)
        decoded = forced_drop_names[reason] or "Unknown"
    elseif tlv_type == 45 then
        local source_port = value_range(0, 2):uint()
        local destination_port = value_range(2, 2):uint()
        item:add(fields.waypoint_source_port, value_range(0, 2))
        item:add(fields.waypoint_destination_port, value_range(2, 2))
        context.waypoint = true
        context.source_port = source_port
        context.destination_port = destination_port
        context.protocol = 17
        decoded = string.format("%d -> %d", source_port, destination_port)
    elseif tlv_type == 20 then
        item:add(fields.source_ipv4, value_range)
        decoded = tostring(value_range:ipv4())
    elseif tlv_type == 21 then
        item:add(fields.source_ipv6, value_range)
        decoded = tostring(value_range:ipv6())
    elseif tlv_type == 39 then
        local tx = value_range(0, 2):uint()
        local rx = value_range(2, 2):uint()
        item:add(fields.path_marking_tx, value_range(0, 2))
        item:add(fields.path_marking_rx, value_range(2, 2))
        decoded = string.format("tx=%d rx=%d", tx, rx)
    elseif tlv_type == 23 then
        if length < 4 then
            item:add_proto_expert_info(
                experts.malformed_tlv,
                "Selective acknowledgement is shorter than its base sequence"
            )
            context.malformed = true
        elseif (length - 4) % 8 ~= 0 then
            item:add_proto_expert_info(
                experts.malformed_tlv,
                "Selective acknowledgement contains a partial block"
            )
            context.malformed = true
        else
            local base_sequence = value_range(0, 4):uint()
            item:add(fields.sack_base_sequence, value_range(0, 4))
            local block_count = (length - 4) / 8
            for block_index = 0, block_count - 1 do
                local block_offset = 4 + block_index * 8
                item:add(fields.sack_left_edge, value_range(block_offset, 4))
                item:add(fields.sack_right_edge, value_range(block_offset + 4, 4))
            end
            decoded = string.format("base=%d blocks=%d", base_sequence, block_count)
        end
    elseif tlv_type == 1 then
        local fragment_info = value_range(6, 2):uint()
        item:add(fields.fragment_extended_id, value_range(0, 4))
        item:add(fields.fragment_original_id, value_range(4, 2))
        item:add(fields.fragment_flags, value_range(6, 2), math.floor(fragment_info / 8192))
        item:add(fields.fragment_offset, value_range(6, 2), fragment_info % 8192)
        item:add(fields.fragment_largest, value_range(8, 2))
        decoded = string.format("fragment id=%d offset=%d",
            value_range(4, 2):uint(), fragment_info % 8192)
    elseif tlv_type == 2 or tlv_type == 3 or tlv_type == 4 or tlv_type == 5 then
        local is_ipv6 = tlv_type == 3 or tlv_type == 5
        local address_length = is_ipv6 and 16 or 4
        local destination_offset = address_length
        local source_port_offset = address_length * 2
        local destination_port_offset = source_port_offset + 2
        local protocol_offset = destination_port_offset + 2
        local source_field = is_ipv6 and fields.session_source_ipv6 or fields.session_source_ipv4
        local destination_field = is_ipv6 and fields.session_destination_ipv6 or fields.session_destination_ipv4
        item:add(source_field, value_range(0, address_length))
        item:add(destination_field, value_range(destination_offset, address_length))
        item:add(fields.session_source_port, value_range(source_port_offset, 2))
        item:add(fields.session_destination_port, value_range(destination_port_offset, 2))
        item:add(fields.session_protocol, value_range(protocol_offset, 1))
        if tlv_type == 2 or tlv_type == 3 then
            context.source_port = value_range(source_port_offset, 2):uint()
            context.destination_port = value_range(destination_port_offset, 2):uint()
            context.protocol = value_range(protocol_offset, 1):uint()
        end
        decoded = string.format("%s:%d -> %s:%d proto=%d",
            tostring(is_ipv6 and value_range(0, address_length):ipv6() or value_range(0, address_length):ipv4()),
            value_range(source_port_offset, 2):uint(),
            tostring(is_ipv6 and value_range(destination_offset, address_length):ipv6() or
                value_range(destination_offset, address_length):ipv4()),
            value_range(destination_port_offset, 2):uint(),
            value_range(protocol_offset, 1):uint())
    elseif tlv_type == 25 then
        item:add(fields.source_nat_ipv4, value_range(0, 4))
        item:add(fields.source_nat_port, value_range(4, 2))
        decoded = string.format("%s:%d", tostring(value_range(0, 4):ipv4()), value_range(4, 2):uint())
    elseif tlv_type == 27 then
        item:add(fields.source_l2_mac, value_range(0, 6))
        item:add(fields.destination_l2_mac, value_range(6, 6))
        decoded = string.format("src=%s dst=%s",
            tostring(value_range(0, 6):ether()), tostring(value_range(6, 6):ether()))
    elseif tlv_type == 51 or tlv_type == 52 then
        local is_ipv6 = tlv_type == 52
        local address_length = is_ipv6 and 16 or 4
        local address_field = is_ipv6 and fields.fib_destination_ipv6 or fields.fib_destination_ipv4
        item:add(address_field, value_range(0, address_length))
        item:add(fields.fib_destination_port, value_range(address_length, 2))
        item:add(fields.fib_protocol, value_range(address_length + 2, 1))
        decoded = string.format("%s:%d proto=%d",
            tostring(is_ipv6 and value_range(0, address_length):ipv6() or value_range(0, address_length):ipv4()),
            value_range(address_length, 2):uint(),
            value_range(address_length + 2, 1):uint())
    elseif tlv_type == 48 then
        local path = value_range(0, 4):uint()
        local priority = value_range(4, 1):uint()
        item:add(fields.path_index, value_range(0, 4))
        item:add(fields.path_priority, value_range(4, 1))
        decoded = string.format("path=%d priority=%d", path, priority)
    elseif tlv_type == 26 then
        local tx = value_range(0, 4):uint()
        local rx = value_range(4, 4):uint()
        local drop_and_count = value_range(8, 2):uint()
        local tx_color = math.floor(tx / 268435456)
        local tx_time = tx % 268435456
        local rx_color = math.floor(rx / 268435456)
        local rx_time = rx % 268435456
        item:add(fields.path_tx_color, value_range(0, 4), tx_color)
        item:add(fields.path_tx_time, value_range(0, 4), tx_time)
        item:add(fields.path_rx_color, value_range(4, 4), rx_color)
        item:add(fields.path_rx_time, value_range(4, 4), rx_time)
        item:add(fields.path_drop, value_range(8, 2), math.floor(drop_and_count / 32768))
        item:add(fields.path_previous_rx_count, value_range(8, 2), drop_and_count % 32768)
        decoded = string.format("tx color=%d time=%d; rx color=%d time=%d; drop=%d previous=%d",
            tx_color, tx_time, rx_color, rx_time,
            math.floor(drop_and_count / 32768), drop_and_count % 32768)
    elseif tlv_type == 28 then
        local flags = value_range:uint()
        decoded = string.format("forward=%s divert=%s sequence=%d",
            math.floor(flags / 32768) % 2 == 1 and "yes" or "no",
            math.floor(flags / 16384) % 2 == 1 and "yes" or "no",
            flags % 4096)
    elseif tlv_type == 46 then
        local kind = value_range:uint()
        decoded = ({[0] = "Unknown", [1] = "Request", [2] = "Response"})[kind] or "Unknown"
    elseif tlv_type == 13 or tlv_type == 31 then
        local value = value_range:uint64()
        item:add(tlv_type == 13 and fields.number_of_sessions or fields.session_capture, value_range)
        decoded = tostring(value)
    elseif tlv_type == 42 then
        local timeout = value_range:uint()
        item:add(fields.remaining_timeout, value_range)
        decoded = tostring(timeout)
    elseif tlv_type == 34 or tlv_type == 44 then
        item:add(fields.dscp, value_range)
        decoded = tostring(value_range:uint())
    elseif tlv_type == 30 or tlv_type == 7 or tlv_type == 10 or tlv_type == 14 or
           tlv_type == 15 or tlv_type == 17 or tlv_type == 19 or tlv_type == 22 or
           tlv_type == 29 or tlv_type == 33 or tlv_type == 35 or tlv_type == 36 or
           tlv_type == 37 or tlv_type == 38 or tlv_type == 41 then
        decoded = value_range:string()
    end

    if decoded then
        item:add(fields.tlv_text, decoded)
        summary[#summary + 1] = name .. "=" .. decoded
    else
        summary[#summary + 1] = name
    end
    return value_offset + length
end

local function parseTlvs(tvb, tree, start_offset, end_offset, section, summary, context)
    local offset = start_offset
    while offset < end_offset do
        if end_offset - offset < 4 then
            tree:add_proto_expert_info(experts.malformed_tlv)
            context.malformed = true
            return false
        end
        local length = tvb(offset + 2, 2):uint()
        if length > end_offset - offset - 4 then
            tree:add_proto_expert_info(experts.malformed_tlv)
            context.malformed = true
            return false
        end
        offset = decodeTlv(tvb, tree, offset, section, summary, context)
    end
    return true
end

local function isPlausiblePayloadTlvs(tvb, start_offset, end_offset)
    local offset = start_offset
    while offset < end_offset do
        if end_offset - offset < 4 then
            return false
        end
        local tlv_type = tvb(offset, 2):uint()
        local length = tvb(offset + 2, 2):uint()
        if not type_names[tlv_type] or header_types[tlv_type] or
           length > end_offset - offset - 4 then
            return false
        end
        local expected = fixed_lengths[tlv_type]
        if expected ~= nil and length ~= expected then
            return false
        end
        if tlv_type == 23 and (length < 4 or (length - 4) % 8 ~= 0) then
            return false
        end
        offset = offset + 4 + length
    end
    return true
end

local function getHeader(tvb)
    if tvb:len() < header_size or tvb(0, 8):raw() ~= cookie then
        return nil
    end
    local version_length = tvb(8, 2):uint()
    local version = math.floor(version_length / 4096)
    local header_length = version_length % 4096
    local payload_length = tvb(10, 2):uint()
    if version ~= 1 or header_length < header_size or
       header_length + payload_length > tvb:len() then
        return nil
    end
    return version, header_length, payload_length
end

local function dissectInnerPayload(tvb, pinfo, tree, offset, length, context)
    if length <= 0 then
        return
    end
    local table_name
    if context.protocol == 6 then
        table_name = "tcp.port"
    elseif context.protocol == 17 or context.waypoint then
        table_name = "udp.port"
    end
    local handle
    if table_name and context.destination_port then
        handle = DissectorTable.get(table_name):get_dissector(context.destination_port)
    end
    if not handle then
        handle = Dissector.get("data")
    end
    if handle then
        handle:call(tvb(offset, length):tvb(), pinfo, tree)
    end
end

local function getHmacLength(tvb, payload_end, root)
    if not svr.prefs.hmac_enabled then
        return 0
    end
    local hmac_length = tonumber(svr.prefs.hmac_length)
    local remaining = tvb:len() - payload_end
    if not hmac_length or not allowed_hmac_lengths[hmac_length] then
        root:add_proto_expert_info(experts.invalid_preference, "Invalid HMAC trailer length preference")
        return 0
    end
    if hmac_length > remaining then
        root:add_proto_expert_info(experts.invalid_length, "HMAC trailer length exceeds packet bounds")
        return 0
    end
    return hmac_length
end

local function decodeHexKey(hex)
    if (#hex ~= 32 and #hex ~= 64) or hex:find("[^%x]") then
        return nil
    end
    return (hex:gsub("..", function(byte)
        return string.char(tonumber(byte, 16))
    end))
end

local function getKeyPreferences(root)
    local text = svr.prefs.keys or ""
    if text ~= key_preference_text then
        key_preference_text = text
        key_preferences = {}
        key_preference_errors = 0
        local seen = {}

        for raw_entry in text:gmatch("[^;]+") do
            local entry = raw_entry:match("^%s*(.-)%s*$")
            local selector, hex = entry:match("^([^=]+)%s*=%s*([%x]+)$")
            local peer
            if selector then
                local scoped_selector, scoped_peer = selector:match("^([^@]+)@([^@]+)$")
                if scoped_selector then
                    selector, peer = scoped_selector, scoped_peer
                end
            end

            local kind, identifier
            if selector then
                kind, identifier = selector:match("^(sid):(%d+)$")
                if not kind then
                    kind, identifier = selector:match("^(rekey):(%d+)$")
                end
                if not kind then
                    kind, identifier = selector:match("^(payload):(%d+)$")
                end
            end

            local numeric_identifier = identifier and tonumber(identifier)
            local max_identifier = kind == "sid" and 4294967295 or 255
            local key = hex and decodeHexKey(hex)
            if not kind or not numeric_identifier or numeric_identifier > max_identifier or
               (selector and selector:find("@", 1, true) and not peer) or not key then
                key_preference_errors = key_preference_errors + 1
            else
                selector = kind .. ":" .. tostring(numeric_identifier)
                local duplicate = selector .. "\0" .. (peer or "")
                if seen[duplicate] then
                    key_preference_errors = key_preference_errors + 1
                else
                    seen[duplicate] = true
                    key_preferences[#key_preferences + 1] = {
                        selector = selector,
                        peer = peer,
                        key = key,
                    }
                end
            end
        end
    end

    if key_preference_errors > 0 then
        root:add_proto_expert_info(
            experts.invalid_preference,
            string.format("%d invalid or duplicate SVR decryption key entries", key_preference_errors)
        )
    end
    return key_preferences
end

local function findDecryptionKey(entries, kind, identifier, pinfo)
    if identifier == nil then
        return nil
    end
    local selector = kind .. ":" .. tostring(identifier)
    local source = tostring(pinfo.src)
    local destination = tostring(pinfo.dst)
    for _, entry in ipairs(entries) do
        if entry.selector == selector and
           (entry.peer == source or entry.peer == destination) then
            return entry.key
        end
    end
    for _, entry in ipairs(entries) do
        if entry.selector == selector and entry.peer == nil then
            return entry.key
        end
    end
    return nil
end

local function getMetadataKey(entries, pinfo, context)
    return findDecryptionKey(entries, "rekey", context.rekey_index, pinfo) or
        findDecryptionKey(entries, "sid", context.security_identifier, pinfo)
end

local function getPayloadKey(entries, pinfo, context)
    return findDecryptionKey(entries, "payload", context.payload_index, pinfo) or
        findDecryptionKey(entries, "sid", context.security_identifier, pinfo)
end

local function decryptData(data, key, aad, root, section_name)
    if not key then
        return nil, "No matching decryption key"
    end
    if not crypto then
        return nil, "Native libgcrypt module unavailable: " .. (crypto_load_error or "unknown load error")
    end

    local cipher = svr.prefs.cipher
    if cipher ~= "aes-cbc" and cipher ~= "aes-gcm" then
        root:add_proto_expert_info(experts.invalid_preference, "Use aes-cbc or aes-gcm for the SVR cipher")
        return nil, "Invalid cipher preference"
    end

    if cipher == "aes-gcm" then
        if #data <= 28 then
            return nil, "AES-GCM section has no ciphertext before its nonce and tag"
        end
        local ciphertext = data:sub(1, #data - 28)
        local nonce = data:sub(-28, -17)
        local tag = data:sub(-16)
        return crypto.decrypt_gcm(key, nonce, ciphertext, tag, aad or "")
    end

    if #data < 32 or (#data - 16) % 16 ~= 0 then
        return nil, "AES-CBC section has invalid ciphertext length"
    end
    local iv = data:sub(-16)
    local ciphertext = data:sub(1, -17)
    local plaintext, err = crypto.decrypt_cbc(key, iv, ciphertext)
    if not plaintext then
        return nil, err
    end
    local final_byte = plaintext:byte(#plaintext)
    local padding_length = final_byte and final_byte + 1 or 0
    if padding_length < 1 or padding_length > 16 or padding_length > #plaintext then
        return nil, "Invalid SSR AES-CBC padding"
    end
    root:add_proto_expert_info(experts.cbc_unverified, section_name .. " uses unauthenticated AES-CBC")
    return plaintext:sub(1, #plaintext - padding_length)
end

local function stringToTvb(value, name)
    local hex = value:gsub(".", function(byte)
        return string.format("%02x", byte:byte())
    end)
    return ByteArray.new(hex):tvb(name)
end

local function addDecryptionFailure(tree, section_name, err)
    tree:add_proto_expert_info(
        experts.decryption_failed,
        section_name .. " decryption unavailable: " .. tostring(err)
    )
end

local function displayCachedPayload(tvb, pinfo, tree, context)
    local root = tree:add(svr, tvb(), "SVR Session Payload")
    if context.rekey_index ~= nil then
        root:add(fields.cached_rekey_index, context.rekey_index):set_generated()
    end
    if context.payload_index ~= nil then
        root:add(fields.cached_payload_index, context.payload_index):set_generated()
    end
    local hmac_length = getHmacLength(tvb, 0, root)
    local payload_length = tvb:len() - hmac_length
    local payload_mode = getMode(svr.prefs.payload_encrypted, "inner payload encryption", root)
    if payload_length > 0 then
        if payload_mode == "never" then
            root:add(fields.inner_payload, tvb(0, payload_length))
            dissectInnerPayload(tvb, pinfo, tree, 0, payload_length, context)
        elseif payload_mode == "always" or
               (payload_mode == "auto" and context.session_encrypted) then
            local keys = getKeyPreferences(root)
            local key = getPayloadKey(keys, pinfo, context)
            local plaintext, err = decryptData(
                tvb(0, payload_length):raw(), key, nil, root, "Inner payload"
            )
            if plaintext then
                local decrypted_tvb = stringToTvb(plaintext, "SVR decrypted inner payload")
                root:add(fields.inner_payload, decrypted_tvb())
                dissectInnerPayload(decrypted_tvb, pinfo, tree, 0, #plaintext, context)
            else
                root:add(fields.encrypted_payload, tvb(0, payload_length))
                addDecryptionFailure(root, "Inner payload", err)
            end
        else
            root:add(fields.opaque_payload, tvb(0, payload_length))
            root:add_proto_expert_info(experts.opaque_encryption)
        end
    end
    if hmac_length > 0 then
        root:add(fields.hmac, tvb(tvb:len() - hmac_length, hmac_length))
    end
    pinfo.cols.protocol:set("SVR")
    local info = "[SVR] cached session payload"
    if context.rekey_index ~= nil and context.payload_index ~= nil then
        info = info .. string.format(" key=%d/%d", context.rekey_index, context.payload_index)
    end
    info = info .. (addKeyCorrelation(root, pinfo, context) or "")
    pinfo.cols.info:set(info)
    return tvb:len()
end

local function displaySvr(tvb, pinfo, tree)
    local version, header_length, payload_length = getHeader(tvb)
    if not version then
        return 0
    end

    local root = tree:add(svr, tvb(), "Secure Vector Routing")
    root:add(fields.cookie, tvb(0, 8))
    root:add(fields.version, tvb(8, 2), version)
    root:add(fields.header_length, tvb(8, 2), header_length)
    root:add(fields.payload_length, tvb(10, 2))

    local summary = {}
    local context = {}
    local header_tree = root:add(tvb(header_size, header_length - header_size), "Header TLVs")
    local header_ok = parseTlvs(tvb, header_tree, header_size, header_length, "header", summary, context)

    local payload_start = header_length
    local payload_end = header_length + payload_length
    context.metadata_encrypted = false
    if payload_length > 0 then
        local payload_tree = root:add(tvb(payload_start, payload_length), "Payload TLVs")
        local metadata_mode = getMode(svr.prefs.md_encrypted, "payload metadata encryption", root)
        local decode_metadata = metadata_mode == "never" or
            (metadata_mode == "auto" and isPlausiblePayloadTlvs(tvb, payload_start, payload_end))
        context.metadata_encrypted = not decode_metadata
        if decode_metadata then
            parseTlvs(tvb, payload_tree, payload_start, payload_end, "payload", summary, context)
        else
            local keys = getKeyPreferences(root)
            local key = getMetadataKey(keys, pinfo, context)
            local aad
            if svr.prefs.cipher == "aes-gcm" and payload_length >= 28 then
                local clear_length = payload_length - 28
                local header = tvb(0, header_length):raw()
                aad = header:sub(1, 10) ..
                    string.char(math.floor(clear_length / 256), clear_length % 256) ..
                    header:sub(13)
            end
            local plaintext, err = decryptData(
                tvb(payload_start, payload_length):raw(),
                key,
                aad,
                root,
                "Payload metadata"
            )
            if plaintext then
                payload_tree:add(fields.encrypted_metadata, tvb(payload_start, payload_length))
                local decrypted_tvb = stringToTvb(plaintext, "SVR decrypted payload metadata")
                local decrypted_tree = payload_tree:add(fields.decrypted_metadata, decrypted_tvb())
                parseTlvs(decrypted_tvb, decrypted_tree, 0, #plaintext, "payload", summary, context)
                context.metadata_encrypted = false
            else
                payload_tree:add(fields.encrypted_metadata, tvb(payload_start, payload_length))
                addDecryptionFailure(payload_tree, "Payload metadata", err)
            end
        end
    end

    local hmac_length = getHmacLength(tvb, payload_end, root)
    local remaining = tvb:len() - payload_end
    local inner_length = remaining - hmac_length
    if inner_length > 0 then
        local payload_mode = getMode(svr.prefs.payload_encrypted, "inner payload encryption", root)
        if payload_mode == "always" then
            local keys = getKeyPreferences(root)
            local key = getPayloadKey(keys, pinfo, context)
            local plaintext, err = decryptData(
                tvb(payload_end, inner_length):raw(), key, nil, root, "Inner payload"
            )
            if plaintext then
                local decrypted_tvb = stringToTvb(plaintext, "SVR decrypted inner payload")
                root:add(fields.inner_payload, decrypted_tvb())
                dissectInnerPayload(decrypted_tvb, pinfo, tree, 0, #plaintext, context)
            else
                root:add(fields.encrypted_payload, tvb(payload_end, inner_length))
                addDecryptionFailure(root, "Inner payload", err)
            end
        elseif payload_mode == "never" then
            root:add(fields.inner_payload, tvb(payload_end, inner_length))
            dissectInnerPayload(tvb, pinfo, tree, payload_end, inner_length, context)
        elseif context.session_encrypted then
            local keys = getKeyPreferences(root)
            local key = getPayloadKey(keys, pinfo, context)
            local plaintext, err = decryptData(
                tvb(payload_end, inner_length):raw(), key, nil, root, "Inner payload"
            )
            if plaintext then
                local decrypted_tvb = stringToTvb(plaintext, "SVR decrypted inner payload")
                root:add(fields.inner_payload, decrypted_tvb())
                dissectInnerPayload(decrypted_tvb, pinfo, tree, 0, #plaintext, context)
            else
                root:add(fields.encrypted_payload, tvb(payload_end, inner_length))
                addDecryptionFailure(root, "Inner payload", err)
            end
        else
            root:add(fields.opaque_payload, tvb(payload_end, inner_length))
            root:add_proto_expert_info(experts.opaque_encryption)
        end
    end
    if hmac_length > 0 then
        root:add(fields.hmac, tvb(tvb:len() - hmac_length, hmac_length))
    end

    if header_ok and not context.malformed then
        cacheSession(pinfo, context)
    end
    pinfo.cols.protocol:set("SVR")
    local info = "[SVR]"
    if #summary > 0 then
        info = info .. " " .. table.concat(summary, ", ")
    end
    if not header_ok then
        info = info .. " malformed header TLVs"
    end
    info = info .. (addKeyCorrelation(root, pinfo, context) or "")
    pinfo.cols.info:set(info)
    return tvb:len()
end

function svr.dissector(tvb, pinfo, tree)
    local result = displaySvr(tvb, pinfo, tree)
    if result == 0 then
        local cached = sessions[flowKey(pinfo)]
        if cached then
            return displayCachedPayload(tvb, pinfo, tree, cached)
        end
        local item = tree:add(svr, tvb(), "Invalid Secure Vector Routing packet")
        item:add_proto_expert_info(experts.invalid_header)
        return tvb:len()
    end
    return result
end

local function heuristic(tvb, pinfo, tree)
    if getHeader(tvb) then
        svr.dissector(tvb, pinfo, tree)
        return true
    end
    local cached = sessions[flowKey(pinfo)]
    if not cached then
        return false
    end
    displayCachedPayload(tvb, pinfo, tree, cached)
    return true
end

svr:register_heuristic("udp", heuristic)
svr:register_heuristic("tcp", heuristic)
DissectorTable.get("udp.port"):add_for_decode_as(svr)
DissectorTable.get("tcp.port"):add_for_decode_as(svr)

svr.prefs.md_encrypted = Pref.string(
    "Payload metadata encryption",
    "auto",
    "Use auto, always, or never; auto parses only a plausible TLV chain"
)
svr.prefs.payload_encrypted = Pref.string(
    "Inner payload encryption",
    "auto",
    "Use auto, always, or never; auto keeps the payload opaque"
)
svr.prefs.hmac_enabled = Pref.bool(
    "HMAC trailer present",
    false,
    "Split configured HMAC bytes from the end of the packet"
)
svr.prefs.hmac_length = Pref.string(
    "HMAC trailer length",
    "16",
    "HMAC bytes to split from packet end (16, 20, 32, 48, or 64)"
)
svr.prefs.cipher = Pref.string(
    "SVR cipher",
    "aes-cbc",
    "Encryption mode for SVR sections: aes-cbc or aes-gcm"
)
svr.prefs.keys = Pref.string(
    "SVR decryption keys",
    "",
    "Semicolon-separated selector=hex-key entries; selectors: sid:N, rekey:N, payload:N; optional @peer"
)

_G["svr_proto"] = svr
return svr
