----------------------------------------
--
-- author: Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, 128 Technology, Inc.
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

require "ast.statement_base"

local ast = _G["ast"]
local syntax = _G["syntax"]


----------------------------------------
-- EnumeratorStatement class, for an "enum" statement's enumerators
--
local EnumeratorStatement = {}
local EnumeratorStatement_mt = { __index = EnumeratorStatement } 
setmetatable( EnumeratorStatement, { __index = ast.StatementBase } ) -- make it inherit from StatementBase
ast:registerClass(nil, "EnumeratorStatement", EnumeratorStatement)

local hex_rgx = GRegex.new("^0[xX]([a-fA-F0-9]+)$")
local oct_rgx = GRegex.new("^0([0-7]+)$")

function EnumeratorStatement:parse(st)
    assert(ast.verifyTokenTTypes("Enumerator", st, "IDENTIFIER", "EQUAL", false))

    local id, idx = ast.Identifier:new(st, 1)
    local name = id:display()

    -- skip the EQUAL
    idx = idx + 1

    local token = st[idx]
    assert(token.ptype == "NUMBER", "Enumerator does not equal a number type")

    local value
    if token.ttype == "INTEGER_LITERAL" then
        value = tonumber(token.value)
    elseif token.ttype == "FLOAT_LITERAL" then
        value = tonumber(token.value)
    elseif token.ttype == "HEX_LITERAL" then
        local val = hex_rgx:match(token.value)
        assert(val, "Could not convert hex='" .. token.value ..
                    " to a number for Enumerator '" .. name .. "'")
        value = tonumber(val, 16)
    elseif token.ttype == "OCTAL_LITERAL" then
        local val = oct_rgx:match(token.value)
        assert(val, "Could not convert octal='" .. token.value ..
                    " to a number for Enumerator '" .. name .. "'")
        value = tonumber(val, 8)
    end

    assert(value, "Could not convert '" .. tostring(token.value) ..
                  " to a number for Enumerator '" .. name .. "'")

    idx = idx + 1

    if idx <= #st then
        assert(st[idx].ttype == "BRACKET_BLOCK",
               "Enumerator '" .. name .. "' has something other than option after number value")
        -- ignore it for now; it doesn't affect encoding on-the-wire(?)
        idx = idx + 1
    end

    assert(idx > #st, "Enumerator '" .. name .. "' has unparsed tokens")

    return id, value
end


function EnumeratorStatement:new(namespace, st)
    local id, value = self:parse(st)
    local new_class = ast.StatementBase:new("ENUMERATOR", id, namespace, value) -- the new instance
    setmetatable( new_class, EnumeratorStatement_mt )
    return new_class
end


function EnumeratorStatement:analyze()
end




----------------------------------------
-- EnumStatement class, for "enum" statements
--
local EnumStatement = {}
local EnumStatement_mt = { __index = EnumStatement } 
setmetatable( EnumStatement, { __index = ast.StatementBase } ) -- make it inherit from StatementBase
ast:registerClass("ENUM", "EnumStatement", EnumStatement, true)


function EnumStatement.preParse(st)
    assert(ast.verifyTokenTTypes("Enum", st, "ENUM", "IDENTIFIER", "BRACE_BLOCK"))
    return ast.Identifier:new(st, 2)
end


function EnumStatement:postParse(st, id, namespace)
    local ns = namespace:addDeclaration(id, self)

    local value  = {}
    for _,tokens in ipairs(st[3].value) do
        if tokens[1].ttype == "OPTION" then
            value[#value+1] = ast.OptionStatement:new(ns, tokens)
        elseif syntax:canTokenBeIdentifier(tokens[1]) then
            value[#value+1] = EnumeratorStatement:new(ns, tokens)
        end
    end

    return ns, value
end


function EnumStatement:new(namespace, st)
    local id = self.preParse(st)
    local new_class = ast.StatementBase:new("ENUM", id)
    setmetatable( new_class, EnumStatement_mt )
    -- call postParse on the new instance
    local ns, value = new_class:postParse(st, id, namespace)
    new_class:setNamespace(ns)
    new_class:setValue(value)
    -- we'll change this during analyze() if the option is set
    new_class["allow_alias"] = false
    return new_class
end


function EnumStatement:analyzeOptions()
    local t = {}
    for _, object in ipairs(self.value) do
        if object:getType() == "OPTION" then
            local is_aa, allow = object:isAllowAlias()
            if is_aa then
                self.allow_alias = allow
            end
        else
            t[#t+1] = object
        end
    end
    self.value = t
end


function EnumStatement:analyzeEnumerators()
    if not self.allow_alias then
        local t = {}
        for _, object in ipairs(self.value) do
            assert(not t[object:getValue()],
                   "Enum '" .. self.id:display()
                   "' has multiple enumerators of the same value but 'allow_alias' is not true")
            t[object:getValue()] = true
        end
    end
end


function EnumStatement:analyze()
    -- see if we have an allow_alias=true option
    -- and remove options from values
    self:analyzeOptions()
    self:analyzeEnumerators()
end


function EnumStatement:getValueString()
    if self.value_string then
        return self.value_string
    end

    local t = {}
    for _, object in ipairs(self.value) do
        t[object:getValue()] = object:getId():display()
    end

    self.value_string = t

    return t
end
