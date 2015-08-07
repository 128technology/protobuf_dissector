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

local StatementBase    = require "ast.statement_base"
local ScopedIdentifier = require "ast.scoped_identifier"


--------------------------------------------------------------------------------
-- The PackageStatement statement class
--
-- Although this is derived from StatementBase, it's not used in the AST;
-- it exists for the front-end to use when determining namespaces and joining
-- the separate file parse trees into one
--
local PackageStatement = {}
local PackageStatement_mt = { __index = PackageStatement }
setmetatable( PackageStatement, { __index = StatementBase } ) -- inherit from StatementBase


function PackageStatement.parse(st)
    dassert(st[1].ttype == "PACKAGE", "Token type is not PACKAGE")

    local id, idx = ScopedIdentifier.new(st, 2)
    dassert(not id:isGlobalScope(), "PackageStatement value cannot have leading period")
    dassert(idx > #st, "Not all PACKAGE statement tokens processed")

    return id
end


function PackageStatement.new(st)
    local id = PackageStatement.parse(st)
    local new_class = StatementBase.new("PACKAGE", id) -- the new instance
    setmetatable( new_class, PackageStatement_mt )
    return new_class
end


function PackageStatement:display()
    return self.id:display()
end


return PackageStatement
