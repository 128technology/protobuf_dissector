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

--[[

    This script is a Lua module (not stand-alone) for proto file syntax
    information.

    This module follows the classic Lua module method of storing
    its public methods/functions in a table and passing back the
    table to the caller of this module file.

]]

-- make sure wireshark is new enough
if not GRegex then
    return nil, "Wireshark is too old: no GRegex library"
end


----------------------------------------
-- our module table that we return to the caller of this script
local syntax = {}


-- table of wiretype info
-- value is the wiretype number encoded on the wire, size is its length
-- -1 sizes are determined at runtime, since they are not fixed sizes
syntax.wiretypes = {
    VARINT = {
        value = 0,
        size  = -1,
    },

    FIXED64 = {
        value = 1,
        size  = 8,
    },

    LENGTH_DELIMITED = {
        value = 2,
        size  = -1,
    },

    START_GROUP = {
        value = 3,
        size  = -1, -- this is actually 0 for this "field"
    },

    END_GROUP = {
        value = 4,
        size  = 0, -- XXX: it's 0 right?
    },

    FIXED32 = {
        value = 5,
        size  = 4,
    },

}


--------------------------------------------------------------------------------
-- the token info table we pass back, for lexing/parsing
-- this table is filled in more later in this module
--[[

    The Token Info table must be a map of tables, with the map keys being
    "COMMENT", STRING", "SYMBOL", "WORD", and "VARIABLE". (there's also
    "BLOCK", but let's ignore that for now)

    Each of those is then an array of sub-tables, where each sub-table
    has the following fields:

        1. 'ttype' = <string>, which is a string ttype that identifies this
                 token. This will be the 'ttype' field used in the lexer's results
                 from tokenization. If no 'ttype' field is given in this sub-table,
                 then it will be the upper-case version of the 'value' field.
        2. 'value' = <string>, the token's string value. For fixed tokens,
                such as the keyword "int32", this identifies the word to look for
                during tokenization, and if found it will be the 'value' field in
                the lexer's results from tokenization. For variable tokens, such
                as an integer literal number, the value cannot be known in advance
                and is thus not in this Token Info table.
        3. 'pattern' = <regex-pattern>, a regex pattern string to use for matching
                the token in the lexer. If this field is not given, then it is
                based on the 'value' field. (case-sensitive, exact match) Note that
                the Token Info table will generate a regex based on these patterns
                in their array order, so more-specific patterns should be put before
                less-specific patterns.
        4. 'ptype' = <string>, a string ttype identifiying a partial type, to group
                tokens into a sub-type, used for parsing and AST building.
        5. 'skip' = <regex-pattern>, a regex pattern to use for skipping portions of
                the file chunk input string. This is only used for "STRING" types.
                A capture group is used to grab relevant value of the string.
        6. 'skip_flags' = <regex-flag-string>, the flags to pass to regex for the
                'skip' regex pattern. ("s" = multiline, U" = ungreedy)
        7. 'wtype' = <string>, the Protobuf wiretype
]]
syntax.token_info = {
    COMMENT =
    {
        {
            ttype   = "LINE_COMMENT",
            pattern = "//",
            skip    = "(.*)",
        },
        {
            ttype   = "BLOCK_COMMENT",
            pattern = "/\\*",
            skip    = "(.*)\\*/",
            skip_flags = "sU",
        },
    },

    STRING =
    {
        {
            ttype   = "DOUBLE_QUOTED_STRING",
            pattern = '"',
            skip    = '((?:[^"\\\\]|\\\\.)*)"',
        },
        {
            ttype   = "SINGLE_QUOTED_STRING",
            pattern = "'",
            skip    = "((?:[^'\\\\]|\\\\.)*)'",
        },
    },

    SYMBOL =
    {
        {
            ttype   = "SEMI",
            value   = ";",
        },
        {
            ttype   = "EQUAL",
            value   = "=",
        },
        {
            ttype   = "PERIOD",
            value   = ".",
            pattern = "\\.",
        },
        {
            ttype   = "COMMA",
            value   = ",",
        },
        {
            ttype   = "L_BRACKET",
            value   = "[",
            pattern = "\\[",
        },
        {
            ttype   = "R_BRACKET",
            value   = "]",
            pattern = "\\]",
        },
        {
            ttype   = "L_PARENS",
            value   = "(",
            pattern = "\\(",
        },
        {
            ttype   = "R_PARENS",
            value   = ")",
            pattern = "\\)",
        },
        {
            ttype   = "L_BRACE",
            value   = "{",
            pattern = "\\{",
        },
        {
            ttype   = "R_BRACE",
            value   = "}",
            pattern = "\\}",
        },
        {
            ttype   = "L_ANGLE",
            value   = "<",
        },
        {
            ttype   = "R_ANGLE",
            value   = ">",
        },
    },

    WORD =
    {
        -- keywords: they don't have a ttype field because
        -- it's auto-generated later, as is the pattern
        {
            value = "double",
            ftype = ftypes.DOUBLE,
            wtype = "FIXED64",
            ntype = "NATIVE",
        },
        {
            value = "float",
            ftype = ftypes.FLOAT,
            wtype = "FIXED32",
            ntype = "NATIVE",
        },
        {
            value = "int32",
            ftype = ftypes.INT32,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "int64",
            ftype = ftypes.INT64,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "uint32",
            ftype = ftypes.UINT32,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "uint64",
            ftype = ftypes.UINT64,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "sint32",
            ftype = ftypes.INT32,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "sint64",
            ftype = ftypes.INT64,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "fixed32",
            ftype = ftypes.UINT32,
            wtype = "FIXED32",
            ntype = "NATIVE",
        },
        {
            value = "fixed64",
            ftype = ftypes.UINT64,
            wtype = "FIXED64",
            ntype = "NATIVE",
        },
        {
            value = "sfixed32",
            ftype = ftypes.INT32,
            wtype = "FIXED32",
            ntype = "NATIVE",
        },
        {
            value = "sfixed64",
            ftype = ftypes.INT64,
            wtype = "FIXED64",
            ntype = "NATIVE",
        },
        {
            value = "bool",
            ftype = ftypes.BOOLEAN,
            wtype = "VARINT",
            ntype = "NATIVE",
        },
        {
            value = "string",
            ftype = ftypes.STRING,
            wtype = "LENGTH_DELIMITED",
            ntype = "NATIVE",
        },
        {
            value = "bytes",
            ftype = ftypes.BYTES,
            wtype = "LENGTH_DELIMITED",
            ntype = "NATIVE",
        },
        {
            value = "group",
            ptype = "STATEMENT",
            ftype = ftypes.BYTES,
            wtype = "START_GROUP",
        },
        {
            value = "required",
            ptype = "LABEL",
        },
        {
            value = "optional",
            ptype = "LABEL",
        },
        {
            value = "repeated",
            ptype = "LABEL",
        },
        {
            value = "message",
            ptype = "DECLARATION",
            -- XXX: should be ftypes.PROTOCOL, but wireshark's Lua can't
            -- handle that apparently (a bug?)
            ftype = ftypes.BYTES,
            wtype = "LENGTH_DELIMITED",
        },
        {
            value = "enum",
            ptype = "DECLARATION",
            ftype = ftypes.INT32,
            wtype = "VARINT",
        },
        {
            value = "import",
            ptype = "STATEMENT",
        },
        {
            value = "syntax",
            ptype = "STATEMENT",
        },
        {
            value = "reserved",
            ptype = "STATEMENT",
        },
        {
            value = "option",  -- careful this doesn't match "optional"
            -- we only care about "allow_alias", "packed", "message_set_wire_format"
            ptype = "STATEMENT",
        },
        {
            value = "map",
            ptype = "STATEMENT",
            ftype = ftypes.BYTES, -- correct? how is this encoded on the wire?
            -- XXX: what is it s wiretype?
        },
        {
            value = "extend",
            ptype = "STATEMENT",
        },
        {
            value = "package",
            ptype = "STATEMENT",
        },
        {
            value = "extensions",
            ptype = "STATEMENT",
        },
        {
            value = "default",
        },
        {
            value = "to",
        },
        {
            value = "max",
        },
    },

    VARIABLE =
    {
        -- everything else...
        -- NOTE: the order matters here, because first match wins in regex
        {
            ttype   = "BOOLEAN_LITERAL",
            pattern = "true|false",
        },
        -- we're going to tokenize periods instead of this
        -- {
        --     ttype   = "SCOPED_IDENTIFIER",
        --     pattern = "\\.?[a-zA-Z](?:[a-z-A-Z0-9_]*)(?:\\.[a-zA-Z](?:[a-z-A-Z0-9_]*))++",
        --     ptype   = "STATEMENT",
        -- },
        {
            ttype   = "IDENTIFIER",
            pattern = "[a-zA-Z](?:[a-z-A-Z0-9_]*)",
            ptype   = "STATEMENT",
        },
        {
            ttype   = "HEX_LITERAL",
            pattern = "0[xX][a-fA-F0-9]+",
            ptype   = "NUMBER",
        },
        {
            ttype   = "FLOAT_LITERAL",
            pattern = "[0-9]+\\.[0-9]+(?:[eE][+-]?[0-9]+)?",
            ptype   = "NUMBER",
        },
        {
            ttype   = "OCTAL_LITERAL",
            pattern = "0[0-7]+",
            ptype   = "NUMBER",
        },
        {
            ttype   = "INTEGER_LITERAL",
            pattern = "[1-9][0-9]*|0",
            ptype   = "NUMBER",
        },
        -- these should only appear inside quoted strings
        -- {
        --     ttype= "HEX_ESCAPED",
        --     pattern = "\\\\[xX][a-fA-F]{2}",
        -- },
        -- {
        --     ttype= "OCTAL_ESCAPED",
        --     pattern = "\\\\[0-7]{3}",
        -- },
        -- we don't want to allow anything else, so don't use this except
        -- for in debugging:
        -- {
        --     ttype= "UNKNOWN",
        --     pattern = "\\S+",
        -- },
    },
    -- not used by lexer, but is used by parser
    BLOCK =
    {
        {
            ttype       = "BRACE_BLOCK",
            begin_ttype = "L_BRACE",
            end_ttype   = "R_BRACE",
        },
        {
            ttype       = "ANGLE_BLOCK",
            begin_ttype = "L_ANGLE",
            end_ttype   = "R_ANGLE",
        },
        {
            ttype       = "BRACKET_BLOCK",
            begin_ttype = "L_BRACKET",
            end_ttype   = "R_BRACKET",
        },
        {
            ttype       = "PARENS_BLOCK",
            begin_ttype = "L_PARENS",
            end_ttype   = "R_PARENS",
        },
    },
}


local categories =
{
    "COMMENT",
    "STRING",
    "SYMBOL",
    "WORD",
    "VARIABLE",
    -- not "BLOCK"
}


-- ptypes which can be head tokens of new statements
local head_ptypes = {
    DECLARATION = true,
    STATEMENT = true,
    LABEL = true,
    -- no comments for now
    -- COMMENT = true,
}


--------------------------------------------------------------------------------

-- fill-in the above table with missing info: generates ttype, pattern, category
for _, category in ipairs(categories) do
    local subtbl = syntax.token_info[category]

    for _, t in ipairs(subtbl) do
        if not t.value then
            -- sanity check: if no value then must have a ttype and pattern
            assert(t.ttype, "Token info table entry with no value/ttype, of pattern: " .. tostring(t.pattern))
            assert(t.pattern, "Token info table entry with no value/pattern, of ttype: " .. tostring(t.ttype))
        else
            -- has a value: ok to not have ttype or pattern
            if not t.ttype then
                t["ttype"] = string.upper(t.value)
            end
            if not t.pattern then
                t["pattern"] = t.value
            end
        end
        t.category = category
    end
end


-- build a table of token ttypes which can be the head of a statement
local tbl = {}
for _, group in ipairs({"WORD", "VARIABLE"}) do
    for _, token in ipairs(syntax.token_info[group]) do
        if token.ptype and head_ptypes[token.ptype] then
            tbl[token.ttype] = true
        end
    end
end
syntax.head_ttypes = tbl


-- build a token list indexed by the token ttypes
tbl = {}
for _, category in ipairs(categories) do
    for _, token in ipairs(syntax.token_info[category]) do
        assert(not tbl[token.ttype], "Token type ttype used more than once: " .. token.ttype)
        tbl[token.ttype] = token
    end
end
syntax.ttype_to_token = tbl


-- build a token list indexed by the token ptypes
tbl = {}
for _, category in ipairs(categories) do
    for _, token in ipairs(syntax.token_info[category]) do
        if token.ptype then
            tbl[token.ptype] = true
        end
    end
end
syntax.ptype_is_token = tbl


-- build a ttype list indexed by value, used by lexer for matching regex captured
-- values to token ttypes; this will only contain "fixed" value types of course
tbl = {}
for _, category in ipairs(categories) do
    for _, token in ipairs(syntax.token_info[category]) do
        if token.value then
            assert(not tbl[token.value], "Token type value used more than once: " .. token.value)
            assert(token.ttype, "Token type missing ttype, value=" .. token.value)
            tbl[token.value] = token
        end
    end
end
syntax.value_to_token = tbl


-- build a table of native ttypes
tbl = {}
for _, token in ipairs(syntax.token_info.WORD) do
    if token.ntype == "NATIVE" then
        tbl[token.ttype] = true
    end
end
syntax.native_types = tbl


-- build a beginning token type to block token table
tbl = {}
for _, token in ipairs(syntax.token_info.BLOCK) do
    tbl[token.begin_ttype] = token
end
syntax.block_begin = tbl


-- build a token type to wtype table, for those which have one
tbl = {}
for _, token in ipairs(syntax.token_info.WORD) do
    if token.wtype then
        tbl[token.ttype] = token.wtype
    end
end
syntax.token_to_wtype = tbl


-- build a on-the-wire wiretype value to wtype table
tbl = {}
for name, subtbl in pairs(syntax.wiretypes) do
    tbl[subtbl.value] = name
end
syntax.wiretype_to_wtype = tbl


-- build a on-the-wire wiretype value to size table
tbl = {}
for name, subtbl in pairs(syntax.wiretypes) do
    tbl[subtbl.value] = subtbl.size
end
syntax.wiretype_to_size = tbl


-- build a wtype to size table
tbl = {}
for name, subtbl in pairs(syntax.wiretypes) do
    tbl[name] = subtbl.size
end
syntax.wtype_to_size = tbl




--------------------------------------------------------------------------------
--
-- the public functions of the module
--
--------------------------------------------------------------------------------

function syntax:concatTokenValues(tokens)
    local t = {}
    for _, token in ipairs(tokens) do
        t[#t+1] = tostring(token.value)
    end
    return table.concat(t)
end


function syntax:tokenBeginsBlock(token)
    return self.block_begin[token.ttype]
end


function syntax:isStatementHeadToken(token)
    return self.head_ttypes[token.ttype]
end


function syntax:isCommentToken(token)
    return token.category == "COMMENT"
end

function syntax:isStringToken(token)
    return token.category == "STRING"
end


function syntax:canTokenBeIdentifier(token)
    return (
            token.ttype == "IDENTIFIER" or
            token.category == "WORD" or
            token.ttype == "BOOLEAN_LITERAL"
           )
end


function syntax:isTokenTtype(ttype)
    return self.ttype_to_token[ttype] ~= nil
end


function syntax:isTokenPtype(ptype)
    return self.ptype_is_token[ptype] ~= nil
end


function syntax:getTokenForTtype(ttype)
    return self.ttype_to_token[ttype]
end


function syntax:getFtypeForTtype(ttype)
    return self.ttype_to_token[ttype].ftype
end


function syntax:getTokenNameForValue(value)
    local t = self.value_to_token[value]
    return t and t.ttype or nil
end


function syntax:isNativeTtype(ttype)
    return self.native_types[ttype]
end


-- for the on-the-wire wiretype to string wtype
function syntax:getWtypeForWiretype(wiretype)
    return self.wiretype_to_wtype[wiretype]
end


function syntax:getWtypeForTtype(ttype)
    return self.token_to_wtype[ttype]
end


-- for the on-the-wire wiretype to size
function syntax:getWiretypeSize(wiretype)
    return self.wiretype_to_size[wiretype]
end


function syntax:getWtypeSize(wtype)
    return self.wtype_to_size[wtype]
end


function syntax:createTokenInstance(ttype, value)
    local token = self:getTokenForTtype(ttype)
    assert(token, "Could not find token for ttype=" .. ttype)
    local copy = {
        ["ttype"]    = token.ttype,
        ["ptype"]    = token.ptype,
        ["category"] = token.category,
        ["value"]    = value,
    }
    return copy
end


function syntax:createBlockToken(token)
    local btoken = self:tokenBeginsBlock(token)
    assert(btoken, "Could not find token for block begin ttype=" .. token.ttype)
    local copy = {
        ["ttype"]       = btoken.ttype,
        ["ptype"]       = btoken.ptype,
        ["category"]    = btoken.category,
        ["begin_ttype"] = btoken.begin_ttype,
        ["end_ttype"]   = btoken.end_ttype,
        ["value"]       = {},
    }
    return copy
end


return syntax
