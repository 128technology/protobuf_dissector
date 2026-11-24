--
-- Copyright (c) 2015, 128 Technology, Inc.
-- Copyright (c) 2026 Hewlett Packard Enterprise Development LP.
--
-- This code is licensed under the MIT license.
--

-- Set this to the absolute path to the project's protobuf.lua.
local protobuf_file = ""

assert(protobuf_file ~= "", "Set protobuf_file in svr_loader.lua to the absolute path to protobuf.lua")
dofile(protobuf_file)
