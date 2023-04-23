# mediaxtream-dissector
A Mediaxtream protocol dissector plugin for Wireshark.

## Overview
The Mediaxtream protocol (Ethertype 0x8912) is used in power line adapters that use Broadcom chipsets and HomePlug technology.

## Limitations
1. No attempt is made to defragment fragmented messages. Messages traversing in-home networks are typically not fragmented.
2. Only a subset of the Management Messages in the Mediaxtream protocol are dissected.
3. The purposes of a few fields in messages are unknown. There is no openly available Mediaxtream protocol documentation.
4. The meanings of the reason codes in error confirmation messages are unknown. Again, there is no openly available Mediaxtream protocol documentation.

## Installation
Copy `mediaxtream.lua` into Wireshark's personal or global [plugin folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
