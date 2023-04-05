# mediaxtream-dissector
A Mediaxtream protocol dissector plugin for Wireshark.

The Mediaxtream protocol (Ethertype 0x8912) is used in power line adapters that use Broadcom chipsets and HomePlug technology.

**Note:** This is a work in progress. Very little has been implemented. Because no documentation for the Mediaxtream protocol has been made available, there will be bugs.

## Installation
Copy `mediaxtream.lua` into Wireshark's personal or global [plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
