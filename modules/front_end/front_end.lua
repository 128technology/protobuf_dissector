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

-- load our modules
local Syntax      = require "syntax"
local FileReader  = require "front_end.file_reader"
local Lexer       = require "front_end.lexer"
local Parser      = require "front_end.parser"
local Ast         = require "ast.ast"
local inspect     = require "inspect"


----------------------------------------
-- our module table that we return to the caller of this script
local FrontEnd = {}


-- lexes+parses a single chunk, returns the created Parse Tree
function FrontEnd:loadChunk(chunk, do_debug, pfunc)
        local token_list = Lexer:lex(chunk)
        assert(token_list, "Could not generate Token List for this chunk: " .. chunk)

        if do_debug then
            Lexer:dump(pfunc, token_list)
        end

        local parse_tree = Parser:parse(token_list)    
        assert(parse_tree, "Could not generate Parse Tree for this chunk: " .. chunk)

        if do_debug then
            pfunc("\n\nParsing complete, got:\n")
            Parser:dump(pfunc, parse_tree)
        end

        return parse_tree
end


-- opens, reads all files in proto_filenames, including lex+parse
-- this is only called at the beginning
function FrontEnd:loadFiles(proto_filenames, do_debug, pfunc)

    local proto_files = FileReader:loadFiles(proto_filenames, do_debug, pfunc)
    assert(proto_files, "Failed to load one or more proto files for compilation")

    if do_debug then
        FileReader:dump(pfunc)
    end

    -- lex and parse the files; after importing we might have to lex and
    -- parse more files, if the imported ones weren't already in this list
    for filename, subtbl in pairs(proto_files) do
        assert(subtbl.chunk, "No chunk for filename: " .. filename)
        proto_files[filename].parse_tree = self:loadChunk(subtbl.chunk, do_debug, pfunc)
    end

    return proto_files
end


-- imports a single file and lexes+parses it, if it hasn't been
-- loaded before; this is only invoked by import()
function FrontEnd:importFile(name, path, proto_files, do_debug, pfunc)
    if proto_files[name] and proto_files[filename].parse_tree then
        -- already loaded it
        return
    end

    proto_files[name] = {}

    local filename = name
    if path then
        filename = path .. name
    end

    local chunk = FileReader:loadFile(filename)
    assert(chunk, "importFile: Failed to get chunk from FileReader:loadFile()")

    local parse_tree = self:loadChunk(chunk, do_debug, pfunc)
    assert(parse_tree, "importFile: Failed to generate Parse Tree from filename: " .. filename)

    proto_files[name].chunk = chunk
    proto_files[name].parse_tree = parse_tree

    -- becomes recursive
    self:callParseTreeImports(parse_tree, proto_files, do_debug, pfunc)
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
    assert(statement[1].ttype == "IMPORT", "getImportFilename called without IMPORT statement")
    assert(#statement > 1, "IMPORT statement too short, missing file to import")
    assert(statement[2].ttype ~= "WEAK", "Weak import statements not supported")

    local idx = 2

    if statement[idx].ttype == "PUBLIC" then
        idx = idx + 1
    end

    assert(Syntax:isStringToken(statement[idx]), "IMPORT statement does not have a string value")

    return statement[idx].value
end


function FrontEnd:callParseTreeImports(parse_tree, path, proto_files, do_debug, pfunc)
    local statement, idx = self:findNextImport(parse_tree, 1)

    while statement do
        local filename = self:getImportFilename(statement)
        self:importFile(filename, path, proto_files, do_debug, pfunc)
        statement, idx = self:findNextImport(parse_tree, idx+1)
    end
end


function FrontEnd:callFileImports(proto_files, do_debug, pfunc)
    for filename, subtbl in pairs(proto_files) do
        assert(subtbl.parse_tree, "No Parse Tree for filename: " .. filename)

        self:callParseTreeImports(subtbl.parse_tree, subtbl.path, proto_files, do_debug, pfunc)
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


local function display(tbl)
    print(inspect(tbl, { filter = inspect.makeFilter({ ".<metatable>" }) }))
end


function FrontEnd:execute(proto_filenames, do_debug, pfunc)
    self:reset()

    local proto_files = self:loadFiles(proto_filenames, do_debug, pfunc)
    assert(proto_files, "Failed to load one or more proto files for compilation")

    -- execute the 'import' statements in the proto files
    self:callFileImports(proto_files, do_debug, pfunc)

    local global_namespace = Ast:build(proto_files)

    --print("The AST:")
    --display(global_namespace)

    return global_namespace
end


return FrontEnd
