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

local StatementBase    = require "ast.statement_base"
local ScopedIdentifier = require "ast.scoped_identifier"


--------------------------------------------------------------------------------
-- The Package statement class
--
-- Although this is derived from StatementBase, it's not used in the AST;
-- it exists for the front-end to use when determining namespaces and joining
-- the separate file parse trees into one
--
local Package = {}
local Package_mt = { __index = Package }
setmetatable( Package, { __index = StatementBase } )


function Package.parse(st)
    assert(st[1].ttype == "PACKAGE", "Token type is not PACKAGE")

    local id, idx = ScopedIdentifier.new(st, 2)
    assert(not id:isGlobalScope(), "Package value cannot have leading period")
    assert(idx > #st, "Not all PACKAGE statement tokens processed")

    return id
end


function Package.new(st)
    local id = Package.parse(st)
    local new_class = StatementBase.new("PACKAGE", id) -- the new instance
    setmetatable( new_class, Package_mt )
    return new_class
end


function Package:display()
    return self.id:display()
end


return Package
