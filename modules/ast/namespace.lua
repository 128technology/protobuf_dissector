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

local AstFactory = require "ast.factory"


----------------------------------------
-- Namespace class
--
local Namespace = {}
local Namespace_mt = { __index = Namespace }


function Namespace.new(name, parent)
    local full_name
    if parent and parent:getFullName() then
        full_name = parent:getFullName() .. "." .. name
    else
        full_name = name
    end

    local new_class = {  -- the new instance
        -- this Namespace's full namespace name (e.g., "foo.bar.qux") or nil
        ["full_name"] = full_name,
        -- this Namespace's local name (e.g., "qux") or nil
        ["name"] = name,
        -- parent Namespace object or nil
        ["parent"] = parent,
        -- map of package/namespace to Namespace objects
        ["children"] = {},
        -- map of enum/message name to their class objects
        ["decls"] = {},
        -- array of AST objects
        ["ast"] = {},
    }
    setmetatable( new_class, Namespace_mt )
    return new_class
end


function Namespace:getType()
    return "NAMESPACE"
end


function Namespace:getFullName()
    return self.full_name
end


function Namespace:getName()
    return self.name
end


function Namespace:getParent()
    return self.parent
end


function Namespace:getChild(name)
    return self.children[name]
end


function Namespace:getDeclaration(name)
    return self.decls[name]
end


function Namespace:buildAst(parse_tree)
    local t = self.ast
    for _, statement in ipairs(parse_tree) do
        if statement[1].ttype ~= "IMPORT" and statement[1].ttype ~= "PACKAGE" then
            t[#t+1] = AstFactory:buildStatement(self, statement)
        end
    end
end


-- adds an Enum or Message object to this
function Namespace:addDeclaration(id, object)
    local ctype = object:getType()
    dassert(ctype == "MESSAGE" or ctype == "ENUM", "Programming error: given wrong class type:", ctype)

    local name = id:display()

    dassert(not self.children[name], "Programming error: Namespace already has name:", name)
    local ns = self.new(name, self)
    self.children[name] = ns

    dassert(not self.decls[name], "Programming error: Namespace already has declaration:", name)
    self.decls[name] = object

    return ns
end


-- adds a Namespace to this one
function Namespace:createChild(name)
    dassert(not self.children[name], "Namespace already has package name:", name)
    dassert(not self.decls[name], "Namespace already has declared name:", name)
    local ns = self.new(name, self)
    self.children[name] = ns
    return ns
end


function Namespace:getRoot()
    local ns = self
    while ns do
        local parent = ns:getParent()
        if not parent then
            return ns
        end
        ns = parent
    end
end


function Namespace:findOrCreateNode(scoped_id, is_find, get_decl)
    local ns = self

    local idx = 1
    local name = scoped_id:getValue(idx)
    dassert(name, "Programming error: could not get initial scoped name")

    local child, prev_name = nil, name

    while name do
        child = ns:getChild(name)
        if not child then
            if is_find then
                return nil
            end
            child = ns:createChild(name)
        end
        ns = child
        idx = idx + 1
        prev_name = name
        name = scoped_id:getValue(idx)
    end

    if get_decl then
        -- we're one level too deep, go back one
        ns = child:getParent()
        dassert(ns, "Could not find scoped identifier '", scoped_id:display(), "'")
        return ns:getDeclaration(prev_name)
    end

    return ns
end


function Namespace:findOrCreateAbsolute(scoped_id)
    local ns = self:getRoot()
    dassert(ns, "Programming error: could not find root")
    return ns:findOrCreateNode(scoped_id)
end


function Namespace:findAbsolute(scoped_id)
    local ns = self:getRoot()
    dassert(ns, "Programming error: could not find root")
    return ns:findOrCreateNode(scoped_id, true)
end


function Namespace:findAbsoluteDeclaration(scoped_id)
    local ns = self:getRoot()
    dassert(ns, "Programming error: could not find root")
    return ns:findOrCreateNode(scoped_id, true, true)
end


-- finds the parent of the named namespace, relative to this one (i.e., goes
-- "up" the tree only)
function Namespace:findParent(name)
    local ns = self:getChild(name)
    if ns then return self end

    ns = self:getParent(name)
    if not ns then
        return nil
    end
    -- recurse
    return ns:findParent(name)
end


function Namespace:findRelativeDeclaration(scoped_id)
    local name = scoped_id:getValue(1)
    dassert(name, "Programming error: could not get initial scoped name")

    -- find first name portion's parent
    local parent = self:findParent(name)
    dassert(parent, "Could not find first portion of scoped identifier '", scoped_id:display(), "'")
    return parent:findOrCreateNode(scoped_id, true, true)
end


local ignore_types = {
    IGNORE = true,
    OPTION = true,
    SYNTAX = true,
    -- remove these, so they end up only being in their namespace's
    -- declaration tables
    MESSAGE = true,
    ENUM = true,
}


function Namespace:analyzeAst()
    local t = {}
    for _, object in ipairs(self.ast) do
        object:analyze()
        if not ignore_types[object:getType()] then
            t[#t+1] = object
        end
    end
    self.ast = t
end


function Namespace:analyzeChildren()
    for _, ns in pairs(self.children) do
        ns:analyze()
    end
end


function Namespace:analyze()
    self:analyzeAst()
    self:analyzeChildren()
    dassert(#self.ast == 0, "Programming error: some statements in AST not analyzed")
end




--------------------------------------------------------------------------------
-- functions for the back_end

function Namespace:createProtocols(proto_table)
    for name, object in pairs(self.decls) do
        if object:getType() == "MESSAGE" then
            proto_table[name] = object:createProtocol()
        end
    end

    for _, ns in pairs(self.children) do
        ns:createProtocols(proto_table)
    end
end


return Namespace
