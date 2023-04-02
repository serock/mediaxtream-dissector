--  SPDX-License-Identifier: GPL-2.0-or-later
------------------------------------------------------------------------
--  pla-util - A Mediaxtream protocol dissector for Wireshark
--  Copyright (C) 2023 John Serock
--
--  This file is part of mediaxtream-dissector.
--
--  mediaxtream-dissector is free software: you can redistribute it
--  and/or modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation, either version 2 of
--  the License, or (at your option) any later version.
--
--  mediaxtream-dissector is distributed in the hope that it will be
--  useful, but WITHOUT ANY WARRANTY; without even the implied warranty
--  of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program. If not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
--  02110-1301, USA.
------------------------------------------------------------------------
local mediaxtream_protocol = Proto("Mediaxtream",  "Gigle Mediaxtream Protocol")

local my_info = {
    description = "A Mediaxtream protocol dissector",
    version = "0.1.0",
    author = "John Serock",
    repository = "https://github.com/serock/mediaxtream-dissector"
}

--  print("Lua version = ", _VERSION)

set_plugin_info(my_info)

local mmtypes = {
    [0xa018] = "Set Key Request (CM_SET_KEY.REQ)",
    [0xa019] = "Set Key Confirmation (CM_SET_KEY.CNF)",
    [0xa020] = "Restart Request (CM_STA_RESTART.REQ)",
    [0xa021] = "Restart Confirmation (CM_STA_RESTART.CNF)",
    [0xa028] = "Network Info Request (CM_NW_INFO.REQ)",
    [0xa029] = "Network Info Confirmation (CM_NW_INFO.CNF)",
    [0xa02c] = "Network Stats Request (CM_NW_STATS.REQ)",
    [0xa02d] = "Network Stats Confirmation (CM_NW_STATS.CNF)",
    [0xa054] = "Factory Reset Request (FW_FACTORY_RESET.REQ)",
    [0xa055] = "Factory Reset Confirmation (FW_FACTORY_RESET.CNF)",
    [0xa070] = "Discover List Request (DISCOVER_LIST.REQ)",
    [0xa071] = "Discover List Confirmation (DISCOVER_LIST.CNF)"
}

local mmelengths = {
    [0xa018] = 22,
    [0xa019] = 4,
    [0xa020] = 5,
    [0xa021] = 4,
    [0xa028] = 6,
    [0xa029] = 1, -- FIXME
    [0xa02c] = 12,
    [0xa02d] = 1, -- FIXME
    [0xa054] = 5,
    [0xa055] = 4,
    [0xa070] = 20
}

local ouis = {
   [0x001f84] = "Gigle Semiconductor"
}

local interfaces = {
    [0x00] = "MII0",
    [0x01] = "MII1",
    [0x02] = "PLC",
    [0x03] = "PLC",
    [0x04] = "SDR",
}

local pf_mmv       = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC)
local pf_mmtype    = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtypes)
local pf_fmi       = ProtoField.uint16("mediaxtream.fmi", "Fragmentation Management Information", base.HEX)
local pf_oui       = ProtoField.uint32("mediaxtream.mme.oui", "Organizationally Unique Identifier", base.HEX, ouis)
local pf_unknown   = ProtoField.uint8("mediaxtream.mme.unknown", "Unknown", base.HEX)
local pf_sig       = ProtoField.bytes("mediaxtream.mme.sig", "Signature", base.SPACE)
local pf_interface = ProtoField.uint8("mediaxtream.mme.interface", "Interface", base.HEX, interfaces)
local pf_hfid_len  = ProtoField.uint8("mediaxtream.mme.hfid_len", "Human-Friendly Identifier Length", base.DEC)
local pf_hfid      = ProtoField.string("mediaxtream.mme.hfid", "Human-Friendly Identifier", base.ASCII)

mediaxtream_protocol.fields = {pf_mmv, pf_mmtype, pf_fmi, pf_oui, pf_unknown, pf_sig, pf_interface, pf_hfid_len, pf_hfid}

local f_mmtype  = Field.new("mediaxtream.mmtype")
local f_hfidlen = Field.new("mediaxtream.mme.hfid_len")

local function get_info()
    local info = f_mmtype().display
    local i, j = string.find(info, "0x")
    info = string.sub(info, 1, i - 3)
    return info
end

local function get_mme_len(buffer)
    local mmtype = f_mmtype()()
    local l = mmelengths[mmtype]
    if l == nil then
        if mmtype == 0xa071 then
            l = 6 + buffer(10, 1):uint()
        end
    end
    return l
end

local function get_hfid_len()
    local l = f_hfidlen()()
    return l
end

function mediaxtream_protocol.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 46 then return end

    pinfo.cols.protocol = mediaxtream_protocol.name

    local subtree = tree:add(mediaxtream_protocol, buffer(), "Mediaxtream Protocol")

    subtree:add_le(pf_mmv,    buffer(0,1))
    subtree:add_le(pf_mmtype, buffer(1,2))
    subtree:add_le(pf_fmi,    buffer(3,2))

    pinfo.cols.info:set(get_info())

    local mme_subtree = subtree:add(buffer(5, get_mme_len(buffer)), "Management Message Entry")

    mme_subtree:add(pf_oui, buffer(5, 3))
    
    local mmtype = f_mmtype()()
    
    if mmtype == 0xa070 then
        mme_subtree:add(pf_unknown, buffer(8, 1))
        mme_subtree:add(pf_sig, buffer(9, 16))
    elseif mmtype == 0xa071 then
        mme_subtree:add(pf_unknown, buffer(8, 1))
        mme_subtree:add(pf_interface, buffer(9, 1))
        mme_subtree:add(pf_hfid_len, buffer(10, 1))
        mme_subtree:add(pf_hfid, buffer(11, get_hfid_len()))
    end
end

local ethertype = DissectorTable.get("ethertype")
ethertype:add(0x8912, mediaxtream_protocol)

