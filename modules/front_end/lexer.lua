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

local Settings    = require "settings"
local dprint2     = Settings.dprint2
local dassert     = Settings.dassert
local Cursor      = require "front_end.cursor"
local Token       = require "front_end.token"

local Lexer = {}

local function numberToken(remaining)
    local value = remaining:match("^%d+%.%d+[eE][+-]?%d+")
        or remaining:match("^%d+%.%d+")
    if value then
        return "FLOAT_LITERAL", value
    end

    value = remaining:match("^0[xX][a-fA-F0-9]+")
    if value then
        return "HEX_LITERAL", value
    end

    value = remaining:match("^0[0-7]+")
    if value then
        return "OCTAL_LITERAL", value
    end

    value = remaining:match("^%d+")
    if value then
        return "INTEGER_LITERAL", value
    end
end

local function readQuotedString(remaining, quote, cursor)
    local position = 2
    while position <= #remaining do
        local character = remaining:sub(position, position)
        if character == "\\" then
            position = position + 2
        elseif character == quote then
            return remaining:sub(1, position), remaining:sub(2, position - 1)
        else
            position = position + 1
        end
    end
    dassert(false, cursor, "Unterminated string")
end

function Lexer:reset(Syntax)
    self.Syntax = Syntax
end

function Lexer:init(Syntax)
    self:reset(Syntax)
end

function Lexer:tokenize(chunk, filename)
    local cursor = Cursor.new(filename, chunk)
    local tokens = {}
    local offset = 1

    while offset <= #chunk do
        local remaining = chunk:sub(offset)
        local whitespace = remaining:match("^[ \t\r\n]+")
        if whitespace then
            cursor:skipWhitespace(whitespace)
            offset = offset + #whitespace
        else
            local ttype
            local value
            local consumed
            local pair = remaining:sub(1, 2)

            if pair == "//" then
                local newline = remaining:find("\n", 3, true)
                consumed = newline and remaining:sub(1, newline - 1) or remaining
                ttype = "LINE_COMMENT"
                value = consumed:sub(3)
            elseif pair == "/*" then
                local close_start = remaining:find("*/", 3, true)
                dassert(close_start, cursor, "Unterminated block comment")
                consumed = remaining:sub(1, close_start + 1)
                ttype = "BLOCK_COMMENT"
                value = remaining:sub(3, close_start - 1)
            elseif remaining:sub(1, 1) == "\"" or remaining:sub(1, 1) == "'" then
                local quote = remaining:sub(1, 1)
                consumed, value = readQuotedString(remaining, quote, cursor)
                ttype = quote == "\"" and "DOUBLE_QUOTED_STRING" or "SINGLE_QUOTED_STRING"
            else
                for _, token in ipairs(self.Syntax.token_info.SYMBOL) do
                    if remaining:sub(1, #token.value) == token.value then
                        consumed = token.value
                        value = token.value
                        ttype = token.ttype
                        break
                    end
                end

                if not consumed then
                    value = remaining:match("^[A-Za-z_][A-Za-z0-9_]*")
                    if value then
                        ttype = self.Syntax:getTokenNameForValue(value)
                        if not ttype then
                            ttype = (value == "true" or value == "false")
                                and "BOOLEAN_LITERAL" or "IDENTIFIER"
                        end
                        consumed = value
                    end
                end

                if not consumed then
                    ttype, value = numberToken(remaining)
                    consumed = value
                end
            end

            dassert(consumed and ttype, cursor,
                    "Could not tokenize input near '", remaining:sub(1, 20), "'")
            tokens[#tokens + 1] = Token.new(ttype, value, cursor)
            cursor:advanceText(consumed)
            offset = offset + #consumed
            dprint2("tokenize: type=", ttype, " value=", value)
        end
    end

    return tokens
end

function Lexer:lex(chunk, filename)
    return self:tokenize(chunk, filename)
end

return Lexer
