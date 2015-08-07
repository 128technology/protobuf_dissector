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

--[[
    This script is a Lua module (not stand-alone) for lexing proto files.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

    How this works:

    The lexer convert strings into a series of tokens, using identifiers for
    known lexemes or regex patterns. For example when it sees a "(" it will
    generate a token with a ttype like OPEN_PAREN and a value of "(".

    This lexer is a simple scanner, without context awareness; for example, if
    the token info table identifies alexeme of "int32" to be a token of ttype
    "INT32", then whenever this lexer sees a lexeme of "int32" it will
    generate a token of "INT32", even if the lexeme is in the location of an
    identifier rather than the keyword. For example this:

        required int64 int32 = 1;

    ... would generate the "INT32" token even though that lexeme happens to be
    a string identifier not the token. So the caller of this lexer needs to
    handle that by analyzin the token results and converting them. The only
    exception to this is with "COMMENT" and STRING" types (sometimes called
    "skip" types in this code), which can grab whole chunks of the input. For
    example, something like this:

        option foo "required int32";

    ... does not generate a "INT32" token, because the whole string will be
    the value of a "DOUBLE_QUOTE_STRING" token.

]]----------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end

local Settings    = require "settings"
local dprint      = Settings.dprint
local dprint2     = Settings.dprint2
local dassert     = Settings.dassert
local derror      = Settings.derror
local debug_level = Settings:getDebugLevel()

local sub = string.sub
local len = string.len

local Cursor = require "front_end.cursor"
local Token  = require "front_end.token"


----------------------------------------
-- our module table that we return to the caller of this script
local Lexer = {}


--------------------------------------------------------------------------------
-- private functions


-- build the variable token table of patterns to be compiled individually
function Lexer:generateVariableMatchPatterns()
    local tbl = {}
    for _, token in ipairs(self.Syntax.token_info.VARIABLE) do
        if not token.value then
            dprint2("creating new variable regex for: ", token.ttype)
            tbl[token.ttype] = GRegex.new("^" .. token.pattern .. "$")
        end
    end
    self.variable_token_regexes = tbl
end


-- build the skip token table of patterns to be compiled individually
function Lexer:generateStringMatchPatterns()
    local tbl = {}
    for _, category in ipairs({"COMMENT", "STRING"}) do
        for _, token in ipairs(self.Syntax.token_info[category]) do
            if not token.value then
                dprint2("creating new string regex for: ", token.ttype)
                tbl[token.ttype] = GRegex.new("^" .. token.pattern .. "$")
            end
        end
    end
    self.skip_token_regexes = tbl
end


-- build the skip table of skip patterns to be compiled individually
function Lexer:generateSkipPatterns()
    local tbl = {}
    for _, category in ipairs({"COMMENT", "STRING"}) do
        for _, token in ipairs(self.Syntax.token_info[category]) do
            if token.skip then
                dprint2("creating new skip regex for: ", token.ttype)
                tbl[token.ttype] = GRegex.new(token.skip, token.skip_flags)
                if not tbl[token.ttype] then
                    error("Could not compile regex for: " .. token.ttype)
                end
            end
        end
    end
    self.skip_regexes = tbl
end


-- make a pattern string of the token info table
function Lexer:makeTokenPatternString()
    local skip, symbol, word, variable = {}, {}, {}, {}

    local token_info = self.Syntax.token_info

    for _, t in ipairs(token_info.COMMENT) do
        skip[#skip + 1] = t.pattern
    end
    for _, t in ipairs(token_info.STRING) do
        skip[#skip + 1] = t.pattern
    end
    for _, t in ipairs(token_info.SYMBOL) do
        symbol[#symbol + 1] = t.pattern
    end
    for _, t in ipairs(token_info.WORD) do
        word[#word + 1] = t.pattern
    end
    for _, t in ipairs(token_info.VARIABLE) do
        variable[#variable + 1] = t.pattern
    end
    return "^(\\s*)((" ..
                table.concat(skip, "|") ..
                    ")|(" ..
                table.concat(symbol, "|") ..
                    ")|(" ..
                table.concat(word, "|") ..
                    ")\\b|(" ..
                table.concat(variable, "|") ..
           "))"
end


-- compile the patterns
function Lexer:compilePatterns()
    self.pattern_strings =
    {
        line_comment        = "//",
        block_comment_begin = "/\\*",
        block_comment_end   = "\\*/",
        comments            = "(//.*|/\\*)",
        dquoted_string      = '"([^"\\\\]|\\\\.)*"',
        squoted_string      = "'([^'\\\\]|\\\\.)*'",
        all_whitespace      = "^\\s+$",
        tokens              = self:makeTokenPatternString(),
    }

    local t = {}
    for ttype, str in pairs(self.pattern_strings) do
        -- Gregex will raise a Lua error if this doesn't succeed
        t[ttype] = GRegex.new(str)
    end
    self.pattern = t
end


-- match the given value to one of the variable/skip token types
function Lexer:matchVariable(value)
    for ttype, regex in pairs(self.variable_token_regexes) do
        if regex:match(value) then
            return ttype
        end
    end
end

-- match the given value to one of the variable/skip token types
function Lexer:matchSkip(value)
    for ttype, regex in pairs(self.skip_token_regexes) do
        if regex:match(value) then
            return ttype
        end
    end
end


-- for the given skip type ttype, skip its content in the chunk
-- returns end offset of skipped portion and the grabbed value
function Lexer:skipChunk(cursor, chunk, begin, ttype)
    local skiprgx = self.skip_regexes[ttype]
    dassert(skiprgx, "Programming error: no compiled regex for skip token:", ttype)

    if debug_level > 1 then
        dprint2("begin=",begin)
        dprint2("chunk at begin=", sub(chunk, begin))
    end

    local start, stop, found = skiprgx:find(chunk, begin)

    return stop, found
end


-- finds each token in chunk and puts it in tokens table
function Lexer:tokenize(chunk, filename)

    local cursor = Cursor.new(filename, chunk)

    -- the table of tokens we find and will return
    local t = {}

    -- normally we'd use Gregex.gmatch() in a for-loop to do this, but we need to
    -- skip quoted strings inside the for-loop, and that can't be done with gmatch;
    -- so we're going to do it the slower way by creating lots of substrings :(
    -- also, GRegex.match() doesn't consider subsequent iterations to match a
    -- pattern with a "^" anchor, which is unfortunate, so by creating substrings
    -- we get to use "^" to prevent skipping unmatched words/tokens

    -- our main regex to use
    local token_rgx = self.pattern.tokens

    local start, stop, whitespace, either, skip, symbol, word, variable = token_rgx:find(chunk)

    while start do
        local ttype, value

        dprint2("tokenize: start=", start, "stop=", stop,
                "found whitespace=", whitespace and true or false,
                "| size=", whitespace and len(whitespace) or 0,
                "| either='", either,
                "' | skip='", skip,
                "' | symbol='", symbol,
                "' | word='", word,
                "' | variable='", variable, "'")

        cursor:skipWhitespace(whitespace)

        if skip then
            -- it matched a pattern that wants to skip stuff (i.e., comments/quoted-strings)
            ttype = self:matchSkip(skip)
            stop, value = self:skipChunk(cursor, chunk, stop+1, ttype)
            dassert(stop, cursor, "Could not skip ahead with: ", ttype)

        elseif symbol or word then
            -- a "fixed" match, meaning the matched text is a word/symbol we know in advance
            local fixed = symbol or word
            value = fixed
            ttype = self.Syntax:getTokenNameForValue(fixed)
            dassert(ttype, cursor, "Programming error: matched fixed-type word '", fixed, "' did not match a token")

        else
            -- when it's not fixed, then we have to figure out which one it matched

            value = variable
            ttype = self:matchVariable(value)
        end

        dassert(ttype, cursor, "Programming error: could not match word '", either, "' to a token")

        -- add it to our tokens table
        t[#t + 1] = Token.new(ttype, value, cursor)

        -- try for the next one
        chunk = sub(chunk, stop+1)
        if len(chunk) == 0 then
            -- we're done
            dprint2("tokenize: chunk end reached")
            return t
        end

        cursor:advanceToChunk(chunk)

        start, stop, whitespace, either, skip, symbol, word, variable = token_rgx:find(chunk)
    end
    dprint2("tokenize: out of while loop with: '", chunk, "'")

    -- sanity check: should only be whitespace left
    start, stop = self.pattern.all_whitespace:find(chunk)
    if not start or (stop < len(chunk)) then
        derror(cursor, "Did not parse all of file", filename, "- had this remaining: '", chunk, "'")
    end

    return t
end



--------------------------------------------------------------------------------
--
-- the public functions of the module
--
--------------------------------------------------------------------------------


-- Reset the lexer; must call init() to use again
function Lexer:reset(Syntax)
    self.Syntax = Syntax
    self.variable_token_regexes = nil
    self.skip_regexes = nil
    self.pattern_strings = nil
    self.patterns = nil
end


-- Initialize the lexer engine with a Token Info table.
function Lexer:init(Syntax)
    self:reset(Syntax)
    self:generateVariableMatchPatterns()
    self:generateStringMatchPatterns()
    self:generateSkipPatterns()
    self:compilePatterns()
end


-- the main public function to do stuff
function Lexer:lex(chunk, filename)
    return self:tokenize(chunk, filename)
end




return Lexer
