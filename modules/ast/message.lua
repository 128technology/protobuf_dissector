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

local AstFactory    = require "ast.ast_factory"
local StatementBase = require "ast.statement_base"
local Identifier    = require "ast.identifier"


--------------------------------------------------------------------------------
-- MessageStatement class, for "Message" statements
--
local MessageStatement = {}
local MessageStatement_mt = { __index = MessageStatement }
setmetatable( MessageStatement, { __index = StatementBase } ) -- make it inherit from StatementBase
AstFactory:registerClass("MESSAGE", "MessageStatement", MessageStatement, true)


function MessageStatement.preParse(st)
    assert(AstFactory.verifyTokenTTypes("Message", st, "MESSAGE", "IDENTIFIER", "BRACE_BLOCK"))
    return Identifier.new(st, 2)
end


function MessageStatement:postParse(st, id, namespace)
    local ns = namespace:addDeclaration(id, self)

    local value  = {}
    for _,tokens in ipairs(st[3].value) do
        value[#value+1] = AstFactory:dispatchBodyStatement(ns, tokens)
    end

    return ns, value
end


function MessageStatement.new(namespace, st)
    local id = MessageStatement.preParse(st)
    local new_class = StatementBase.new("MESSAGE", id)
    setmetatable( new_class, MessageStatement_mt )
    -- call postParse on the new instance
    local ns, value = new_class:postParse(st, id, namespace)
    new_class:setNamespace(ns)
    new_class:setValue(value)
    return new_class
end


local ignore_types = {
    OPTION = true,
    -- remove these, so they end up only being in their namespace's
    -- declaration tables
    MESSAGE = true,
    ENUM = true
}

function MessageStatement:analyze()
    local t = {}
    for _, object in ipairs(self.value) do
        object:analyze()
        if not ignore_types[object:getType()] then
            t[#t+1] = object
        end
    end
    self.value = t
end


--local range_comma_rgx = GRegex.new("([^,]+),?")
local range_rgx = GRegex.new("([0-9]+)\\s*(?:-\\s*([0-9]+))?")
local function marshallRange(range)
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




--------------------------------------------------------------------------------
-- functions for the back_end

local Decoder = require "back_end.decoder"
local MessageDecoder = require "back_end.message"
local PacketDecoder = require "back_end.packet"


function MessageStatement:createPrefs()
    local proto = self.proto

    assert(proto, "Programming error: MessageStatement:createPrefs() called without created Proto")

    -- local udp_ports = self.udp_ports
    local udp_ports = "0"
    proto.prefs.udp_ports = Pref.range("UDP port range for protocol", udp_ports, "The range of UDP port numbers to decode the protocol for", 65535)

    -- this creates a new function, so the local udp_ports variable is saved as an
    -- upvalue and does not need to be stored in the self/proto object
    proto.prefs_changed = function()
        if udp_ports ~= proto.prefs.udp_ports then
            -- remove old ports, if not 0
            if udp_ports ~= "0" then
                for port in pairs(marshallRange(udp_ports)) do
                    DissectorTable.get("udp.port"):remove(port, proto)
                end
            end

            -- save new range
            udp_ports = proto.prefs.udp_ports

            -- add new ports, if not 0
            if udp_ports ~= "0" then
                for port in pairs(marshallRange(udp_ports)) do
                    DissectorTable.get("udp.port"):add(port, proto)
                end
            end
        end
    end
end


function MessageStatement:createTagTable()
    if not self.tag_table then
        local tags, pfields = {}, {}

        for _, field in ipairs(self.value) do
            local pfield = field:getProtoField()
            pfields[#pfields+1] = pfield
            tags[field:getTag()] = field:getDecoder(pfield, field:getTag(), field:getName())
        end

        self.tag_table = tags
        self.pfields = pfields
    end
    return self.tag_table
end


-- this is invoked by both the Field class and the Message class; for
-- the Field class it's done to get a decoder for the Message as a field
-- inside another Message/Group; when done by the Message class, it's to
-- get a decoder to use as the initial one when dissecting a top-level
-- Message (i.e., dissect itself), in which case the tag will be 0 and
-- the name will be the same as the Proto object's protocol name
function MessageStatement:getDecoder(pfield, tag, name)
    self:createProto()
    self:createTagTable()
    assert(self.proto, "Programming error: Proto not created")
    return MessageDecoder.new(pfield, tag, name, self.proto, self.id:display(), self.tag_table)
end


-- this creates the wireshark Proto.dissector function, used if this
-- Message is the top-level Message of a packet
function MessageStatement:createDissector()
    -- this gets a decoder for the Proto object only, not a field
    local decoder = PacketDecoder.new(self.proto, self.tag_table)

    -- this creates a new function, so local variables are saved as upvalues
    -- and do not need to be stored in the self/proto object
    self.proto.dissector = function(tvbuf,pktinfo,root)
        return Decoder.new(tvbuff, pktinfo, root):decode(decoder)
    end
end


-- createProto() is called to create a full dissector implementation for a
-- Message - i.e., it creates the Proto object and Prefs and so on: things
-- done only once for a given Message object, to make it a fully stand-alone
-- Protocol dissector. To accomplish that, it invokes getDecoder() for
-- everything in it, including other Message objects, but unlike this
-- createProto() function, the getDecoder() only creates the stuff needed to
-- be fields within a Massage - essentially the ProtoFields and such.
function MessageStatement:createProto()
    --assert(not self.proto, "Programming error: MessageStatement:createProto() called more than once")
    if not self.proto then

        self.proto = Proto.new(self.namespace:getFullName(), self.id:display())

        self:createTagTable()

        -- register the ProtoFields
        self.proto.fields = self.pfields

        self:createDissector()

        self:createPrefs()
    end

    return self.proto
end


function MessageStatement:createProtocol()
    local t = {}
    t.proto = self:createProto()
    t.tag_table = self:createTagTable()
    return t
end

return  MessageStatement
