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

local AstFactory       = require "ast.factory"
local StatementBase    = require "ast.statement_base"
local ScopedIdentifier = require "ast.scoped_identifier"


----------------------------------------
-- OptionStatement class, for "option" statements
--
local OptionStatement = {}
local OptionStatement_mt = { __index = OptionStatement }
setmetatable( OptionStatement, { __index = StatementBase } ) -- inherit from StatementBase
AstFactory:registerClass("OPTION", "OptionStatement", OptionStatement, true)

function OptionStatement.parse(st)
    dassert(AstFactory.verifyTokenTTypes("Option", st, "OPTION", false, false))

    local id, idx = "", 2
    if st[idx].ttype == "PARENS_BLOCK" then
        local subtbl = st[2].value
        dassert(#subtbl > 0, "OPTION fullIdent not given")
        id = ScopedIdentifier.new(subtbl, 1)
        idx = idx + 1
        if st[idx].ttype == "PERIOD" then
            -- skip the ".ident" portion and get to the equal
            while #st > idx and st[idx].ttype ~= "EQUAL" do
                idx = idx + 1
            end
        end
    else
        id, idx = ScopedIdentifier.new(st, idx)
    end

    dassert(st[idx].ttype == "EQUAL", "OPTION statement without an '='")
    dassert(#st > idx, "OPTION statement missing constant after '='")
    idx = idx + 1

    local value = AstFactory.serializeRemaining(st, idx)
    return id, value
end


function OptionStatement.new(namespace, st)
    local id, value = OptionStatement.parse(st)
    local new_class = StatementBase.new("OPTION", id, namespace, value) -- the new instance
    setmetatable( new_class, OptionStatement_mt )
    return new_class
end


function OptionStatement:isAllowAlias()
    if self.id:display() == "allow_alias" then
        return true, self.value == "true"
    end
end


local option_not_supported = {
    ["message_set_wire_format"] = true,
    ["packed"] = true
}


function OptionStatement:analyze()
    if option_not_supported[self.id:display()] then
        derror("Option '", self.id:display(), "' is not supported")
    end
end


return OptionStatement
