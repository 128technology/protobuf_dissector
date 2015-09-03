# Wireshark Protobuf Dissector
A Wireshark Lua plugin to decode/dissect Google Protobuf messages

This is a full Wireshark plugin to display [Google Protobuf](https://developers.google.com/protocol-buffers/) message packets, with the following features:
* **Custom proto file decode**: give it your .proto files, and it will decode them in UDP packets, using their field names, enum values, etc.
* **Generic protobuf decode**: don't give it your .proto files, and it will decode generic protobuf info.
* **Protobuf v2 support**: supports almost every field type that exists in Protobuf v2. (see Limitations below)
* **Expert info for missing things**: generates Wireshark expert info if a required field is missing, or if two oneof fields are used, etc.
* **Does not require any code compiling**: since it's a set of pure Lua scripts, you don't need to compile anything. You just need Wireshark version 1.12 or higher.
* **Both Wireshark and tshark support**: it works in either program.

This plugin is similar in concept to the [protobuf-wireshark](https://code.google.com/p/protobuf-wireshark/) project, except this one doesn't require any C++ compiling. (and the other one appears to be dead)


## Usage:
Copy this entire directory of files into your Wireshark "Personal Plugins" folder. You can skip/ignore the "test" directory, but not the others. If you have one or more .proto files to use, put them in the "files" directory.

**Tip**: to find out where your Personal Plugins folder is, open Wireshark and go to **Help->About Wireshark** and it will be listed in the **Folders** tab. You may need to create the folder the first time.

Then start Wireshark, open a file with your Protobuf packets, select one of those packets, right-click and select "Decode as..." and scroll down to the name of your outer-most Message type. To make this happen all the time for a UDP port, go to "Edit->Preferences->Protocols", fnd your outer-most Message type, and put the UDP port number in the field shown (or a range of port numbers if it can be more than one port).

The "outer-most Message type" is the Protobuf 'message' identifier name in your .proto file, but in all capital letters. You'll see that every Protobuf 'message' idenfitier name creates a new protocol in Wireshark; you can use one or all of them a the outer-most Message type. (see details in the 'How it works' section below)

If you do not have a .proto file definition to decode with, then select the protocol "PROTOBUF", which is the generic dissector.

**Note**: this plugin cannot load new .proto files while Wireshark is running - if you want to modify, add, or delete .proto files you must restart Wireshark/tshark for the changes to take effect. (this is due to a Wireshark limitation, and might be fixed in Wireshark v2.0)


**Example screenshot:**
TODO: add the screeenshot, once the repo is up on github
![*Screenshot of plugin in use](https://cloud.githubusercontent.com/assets/[fill me in])


## Compatibility
Requires Wireshark version 1.12.0 or higher.


## License
Copyright (c) 128 Technology, Inc. MIT license. See the LICENSE.md file for details.


## Limitations:
* The protobuf 'extensions' mechanism is not truly supported - you can have 'extensions' statements in your .proto files, but this plugin will ignore them and decode any fields using the extension range as unknown protobuf fields. Likewise, the 'extend' statement is ignored. I didn't implement them because (1) it's not trivial to add, (2) we don't use them in my company, and (3) everyone I've asked about it thinks they're a bad idea anyway. If you need extension support, please open an issue.
* The "packed=true" option for repeated fields is not yet supported, and will generate an error currently. This is on the TODO list as a high priority.
* The "message_set_wire_format=true" option is not supported, as it's an internal option only used by Google for legacy version 1 support.
* All other options are summarily ignored, as they should not affect on-the-wire encoding/decoding. If that's not the case, please open an issue.
* The 'import' statement 'weak' mode is not supported, and will generate an error if used. The 'weak' mode allows the imported file to be ignored if it can't be found, but that seems contradictory to decoding its values with this plugin. If you need weak mode support, please open an issue.
* Loading new .proto files while Wireshark is running is not supported - if you want to modify, add, or delete .proto files you must restart Wireshark/tshark for the changes to take effect. (this is due to a Wireshark limitation, and might be fixed in Wireshark v2.0)


## How it works:
The plugin implements a "compiler" for .proto file syntax, which converts the .proto file contents into Wireshark `Proto` and `ProtoField` objects and run-time dissector functions. This takes quite a bit of code and goes through various stages of "compilation", but the details of that won't be described here.

Each protobuf 'message', whether at file level or within another 'message', is registered as a Wireshark Lua `Proto` protocol object using its fully scoped name. For example a .proto file definition of "message foo {...}" will create a "FOO" protocol. If that 'foo' message had another message defined inside of it, named "bar", then that internal one would become a "FOO.BAR" protocol. If that .proto file had a 'package' statement, such as "package qux;", then that is part of the scope, and the created protocol name would be "QUX.FOO" for the outer message, and "QUX.FOO.BAR" for the inner. Each of these message protocols get their own preferences, and can be used independently for dissecting packets. (As they can be used independently in Google's protobuf libraries.)

Each field inside a 'message' becomes a Wireshark Lua `ProtoField` object, registered in its encompassing message's `Proto` object. The `ProtoField` type is based on the protobuf types: a protobuf 'int32' becomes an `int32` `ProtoField` type, as do 'sint32' and 'sfixed32'; a 'group' becomes a `bytes` `ProtoField` type, etc. Protobuf 'enum' statements generate value-string tables for the fields that use them, which are passed into the relevant `ProtoField` objects. If a field inside a message actually identifies another message, that linkage is resolved as well. And so on.


## TODO:
* Support TCP somehow. Right now it's just Protobuf in UDP. Technically Protobuf can't be sent natively in TCP, because it has no framing to delimit the outer message (it would never end, technically). There are some tricks people play, however, to get it to work over TCP.
* Support the 'default' option such that we show it as a generated field value if it's not in the packet.
* Support packed encoding mode for v2 - i.e., the "packed=true" option for repeated statements.
* Support Protobuf v3. There isn't much difference between v2 and v3 in terms of on-the-wire encoding. Mostly it's just that it's always in packed encoding mode, and there's a new "map" type, which is really just encoded like a message. So I think adding v3 support might be easy.
* Support "weak" 'import' statements in terms of pretending they're not weak and opening their file or erroring - right now we just error if we see 'weak' import statements.
* Allow doxygen-like comments in .proto files, to let the user change the names, text to display, etc.
* Support re-loading .proto files whle Wireshark is running, once the plumbing for that is available in Wireshark v2.0. (it was just added to Wireshark recently, but is experimental)
