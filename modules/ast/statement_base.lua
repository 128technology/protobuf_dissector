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


local Base = require "ast.base"


--------------------------------------------------------------------------------
-- The StatementBase base class, from which others derive
--
-- All Statements have a type, identifier, parent namespace, value.
-- The identifier is a Identifier or ScopedIdentifier object
-- The value is a string, number, table, etc. - the deriving class decides
-- what it is and how to work with it.
--
local StatementBase = {}
local StatementBase_mt = { __index = StatementBase }
setmetatable( StatementBase, { __index = Base } ) -- inherit from Base


function StatementBase.new(ttype, id, namespace, value)
    local new_class = Base.new(ttype) -- the new instance
    new_class["id"] = id
    new_class["namespace"] = namespace
    new_class["value"] = value
    setmetatable( new_class, StatementBase_mt )
    return new_class
end


------------------------------------------
-- protected functions

-- in some cases we don't really know the value until after construction
function StatementBase:setValue(value)
    self.value = value
end


-- in some cases we don't really know the namespace until after construction
function StatementBase:setNamespace(namespace)
    self.namespace = namespace
end


------------------------------------------
-- public functions

function StatementBase:getId()
    return self.id
end


function StatementBase:getName()
    return self.id:display()
end


function StatementBase:getNamespace()
    return self.namespace
end


function StatementBase:getValue()
    return self.value
end


return StatementBase

