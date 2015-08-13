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

    This script is a Lua module (not stand-alone) for handling the "front-end" of
    the compiler. A compiler front-end handles file reading, lexical analysis,
    parsing (Syntax analysis), and semantic analysis. In this module's case, it
    coordinates/controls the execution of the front-end roles, but the actual
    work is mostly performed in sub-modules:

    1. The "FileReader" module handles os-level file opening and reading.
    2. The "Lexer" module scans the read in chunks into lists of tokens
       (called a "Token List").
    3. The "Parser" module converts a Token List into a Parse Tree,
       replacing group symbols such as "{"/"}" into Block token tables.
    4. The "Ast" module converts the Parse Tree into an Abstract Syntax Tree
       (AST), consisting of class objects representing each statement.

    This module follows the classic Lua module method of storing its public
    methods/functions in a table and passing back the table to the caller of
    this module file.

]]

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings  = require "settings"
local dprint    = Settings.dprint
local dprint2   = Settings.dprint2
local dassert   = Settings.dassert

-- load our modules
local Syntax     = require "syntax"
local FileReader = require "front_end.file_reader"
local Lexer      = require "front_end.lexer"
local Parser     = require "front_end.parser"
local Ast        = require "ast.ast"
local inspect    = require "inspect"


----------------------------------------
-- our module table that we return to the caller of this script
local FrontEnd = {}


-- lexes+parses a single chunk, returns the created Parse Tree
function FrontEnd:loadChunk(chunk, filename)
        local token_list = Lexer:lex(chunk, filename)
        dassert(token_list, "Could not generate Token List from filename:", filename, "for this chunk: '", chunk, "'")


        dprint2("\nThe Lexer's generated Token List table:", token_list)

        local parse_tree = Parser:parse(token_list)
        dassert(parse_tree, "Could not generate Parse Tree from filename:", filename, "for this chunk: '", chunk, "'")

        dprint2("\n\nParsing complete, got Parse Tree:", parse_tree)

        return parse_tree
end


-- opens, reads all files in proto_filenames, including lex+parse
-- this is only called at the beginning
function FrontEnd:loadFiles(proto_filenames)

    local proto_files = FileReader:loadFiles(proto_filenames)
    dassert(proto_files, "Failed to load one or more proto files for compilation")

    dprint2("The proto files:", proto_files)

    -- lex and parse the files; after importing we might have to lex and
    -- parse more files, if the imported ones weren't already in this list
    for filename, subtbl in pairs(proto_files) do
        dassert(subtbl.chunk, "No chunk for filename:", filename)
        proto_files[filename].parse_tree = self:loadChunk(subtbl.chunk, filename)
    end

    return proto_files
end


-- imports a single file and lexes+parses it, if it hasn't been
-- loaded before; this is only invoked by import()
function FrontEnd:importFile(name, path, proto_files)
    if proto_files[name] and proto_files[name].parse_tree then
        -- already loaded it
        return
    end

    proto_files[name] = {}

    local filename = name
    if path then
        filename = path .. name
    end

    local chunk = FileReader:loadFile(filename)
    dassert(chunk, "Failed to get chunk from FileReader:loadFile() for filename", filename)

    local parse_tree = self:loadChunk(chunk, filename)
    dassert(parse_tree, "Failed to generate Parse Tree from filename: ", filename)

    proto_files[name].chunk = chunk
    proto_files[name].parse_tree = parse_tree

    -- becomes recursive
    self:callParseTreeImports(parse_tree, proto_files)
end


function FrontEnd:findNextImport(parse_tree, idx)
    if idx > #parse_tree then
        return nil
    end

    while idx <= #parse_tree do
        local token = parse_tree[idx][1]

        if token.ttype == "IMPORT" then
            return parse_tree[idx], idx
        end
        idx = idx + 1
    end
end


function FrontEnd:getImportFilename(statement)
    dassert(statement[1].ttype == "IMPORT", "Programming error: getImportFilename called without IMPORT statement")
    dassert(#statement > 1, "IMPORT statement too short, missing file to import")
    dassert(statement[2].ttype ~= "WEAK", "Weak import statements not supported")

    local idx = 2

    if statement[idx].ttype == "PUBLIC" then
        idx = idx + 1
    end

    dassert(Syntax:isStringToken(statement[idx]), "IMPORT statement does not have a string value")

    return statement[idx].value
end


function FrontEnd:callParseTreeImports(parse_tree, path, proto_files)
    local statement, idx = self:findNextImport(parse_tree, 1)

    while statement do
        local filename = self:getImportFilename(statement)
        self:importFile(filename, path, proto_files)
        statement, idx = self:findNextImport(parse_tree, idx+1)
    end
end


function FrontEnd:callFileImports(proto_files)
    for filename, subtbl in pairs(proto_files) do
        dassert(subtbl.parse_tree, "No Parse Tree for filename:", filename)

        self:callParseTreeImports(subtbl.parse_tree, subtbl.path, proto_files)
    end
end




--------------------------------------------------------------------------------
-- the public functions of the module


function FrontEnd:reset()
end


function FrontEnd:init()
    Lexer:init(Syntax)
    Parser:init(Syntax)
    Ast:init(Syntax)
end


function FrontEnd:execute(proto_filenames)
    self:reset()

    local proto_files = self:loadFiles(proto_filenames)
    dassert(proto_files, "Failed to load one or more proto files for compilation", proto_filenames)

    -- execute the 'import' statements in the proto files
    self:callFileImports(proto_files)

    local global_namespace = Ast:build(proto_files)

    dprint2("The AST:", global_namespace)

    return global_namespace
end


return FrontEnd
