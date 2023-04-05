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

local ETHERTYPE_MEDIAXTREAM = 0x8912

local MMTYPE_SET_KEY_REQ       = 0xa018
local MMTYPE_SET_KEY_CNF       = 0xa019
local MMTYPE_STA_RESTART_REQ   = 0xa020
local MMTYPE_STA_RESTART_CNF   = 0xa021
local MMTYPE_NW_INFO_REQ       = 0xa028
local MMTYPE_NW_INFO_CNF       = 0xa029
local MMTYPE_NW_STATS_REQ      = 0xa02c
local MMTYPE_NW_STATS_CNF      = 0xa02d
local MMTYPE_FACTORY_RESET_REQ = 0xa054
local MMTYPE_FACTORY_RESET_CNF = 0xa055
local MMTYPE_GET_PARAM_REQ     = 0xa05c
local MMTYPE_GET_PARAM_CNF     = 0xa05d
local MMTYPE_DISCOVER_LIST_REQ = 0xa070
local MMTYPE_DISCOVER_LIST_CNF = 0xa071

set_plugin_info(my_info)

local mmtypes = {
    [MMTYPE_SET_KEY_REQ]       = "Set Key request",
    [MMTYPE_SET_KEY_CNF]       = "Set Key confirmation",
    [MMTYPE_STA_RESTART_REQ]   = "Restart request",
    [MMTYPE_STA_RESTART_CNF]   = "Restart confirmation",
    [MMTYPE_NW_INFO_REQ]       = "Network Info request",
    [MMTYPE_NW_INFO_CNF]       = "Network Info confirmation",
    [MMTYPE_NW_STATS_REQ]      = "Network Stats request",
    [MMTYPE_NW_STATS_CNF]      = "Network Stats confirmation",
    [MMTYPE_FACTORY_RESET_REQ] = "Factory Reset request",
    [MMTYPE_FACTORY_RESET_CNF] = "Factory Reset confirmation",
    [MMTYPE_GET_PARAM_REQ]     = "Get Parameter request",
    [MMTYPE_GET_PARAM_CNF]     = "Get Parameter confirmation",
    [MMTYPE_DISCOVER_LIST_REQ] = "Discover List request",
    [MMTYPE_DISCOVER_LIST_CNF] = "Discover List confirmation"
}

local mmelengths = {
    [MMTYPE_SET_KEY_REQ]       = 22,
    [MMTYPE_SET_KEY_CNF]       = 4,
    [MMTYPE_STA_RESTART_REQ]   = 5,
    [MMTYPE_STA_RESTART_CNF]   = 4,
    [MMTYPE_NW_INFO_REQ]       = 6,
    [MMTYPE_NW_INFO_CNF]       = 1, --  FIXME
    [MMTYPE_NW_STATS_REQ]      = 12,
    [MMTYPE_NW_STATS_CNF]      = 1, --  FIXME
    [MMTYPE_FACTORY_RESET_REQ] = 5,
    [MMTYPE_FACTORY_RESET_CNF] = 4,
    [MMTYPE_GET_PARAM_REQ]     = 5,
    [MMTYPE_DISCOVER_LIST_REQ] = 20
}

local ouis = {
   ["00:1f:84"] = "Gigle Semiconductor"
}

local interfaces = {
    [0x00] = "MII0",
    [0x01] = "MII1",
    [0x02] = "PLC",
    [0x03] = "PLC",
    [0x04] = "SDR",
}

local params = {
    [0x07] = "Manufacturer NID",
    [0x08] = "Manufacturer NMK",
    [0x09] = "Manufacturer DAK part 1 of 4",
    [0x0a] = "Manufacturer DAK part 2 of 4",
    [0x0b] = "Manufacturer DAK part 3 of 4",
    [0x0c] = "Manufacturer DAK part 4 of 4",
    [0x1b] = "Manufacturer STA HFID",
    [0x1c] = "Manufacturer AVLN HFID",
    [0x23] = "User NID",
    [0x24] = "User NMK",
    [0x25] = "User STA HFID",
    [0x26] = "User AVLN HFID"
}

local pf_mmv             = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC)
local pf_mmtype          = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtypes)
local pf_fmi             = ProtoField.uint16("mediaxtream.fmi", "Fragmentation Management Information", base.HEX)
local pf_oui             = ProtoField.bytes("mediaxtream.mme.oui", "Organizationally Unique Identifier", base.COLON)
local pf_seq_num         = ProtoField.uint8("mediaxtream.mme.seqNum", "Sequence Number", base.DEC)
local pf_sig             = ProtoField.bytes("mediaxtream.mme.sig", "Signature", base.SPACE)
local pf_interface       = ProtoField.uint8("mediaxtream.mme.interface", "Interface", base.HEX, interfaces)
local pf_hfid_len        = ProtoField.uint8("mediaxtream.mme.hfidLen", "Human-Friendly Identifier Length", base.DEC)
local pf_hfid            = ProtoField.string("mediaxtream.mme.hfid", "Human-Friendly Identifier", base.ASCII)
local pf_param           = ProtoField.uint8("mediaxtream.mme.param", "Parameter", base.HEX, params)
local pf_octets_per_elem = ProtoField.uint8("mediaxtream.mme.param.octetsPerElem", "Octets per Element", base.DEC)
local pf_num_elems       = ProtoField.uint16("mediaxtream.mme.param.numElems", "Number of Elements", base.DEC)
local pf_param_string    = ProtoField.string("mediaxtream.mme.param.string", "Parameter Value", base.ASCII)
local pf_param_uint32    = ProtoField.uint32("mediaxtream.mme.param.uint32", "Parameter Value", base.HEX)

mediaxtream_protocol.fields = {
    pf_mmv, pf_mmtype, pf_fmi, pf_oui, pf_seq_num, pf_sig, pf_interface, pf_hfid_len, pf_hfid, pf_param, pf_octets_per_elem, pf_num_elems, pf_param_string, pf_param_uint32}

local f_mmtype          = Field.new("mediaxtream.mmtype")
local f_oui             = Field.new("mediaxtream.mme.oui")
local f_hfidlen         = Field.new("mediaxtream.mme.hfidLen")
local f_octets_per_elem = Field.new("mediaxtream.mme.param.octetsPerElem")
local f_num_elems       = Field.new("mediaxtream.mme.param.numElems")

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
        if mmtype == MMTYPE_DISCOVER_LIST_CNF then
            l = 6 + buffer(10, 1):uint()
        elseif mmtype == MMTYPE_GET_PARAM_CNF then
            l = 7 + buffer(9, 1):le_uint() * buffer(10, 2):le_uint()
        end
    end
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
    mme_subtree:add(pf_oui, buffer(5, 3)):append_text(" ("):append_text(ouis[f_oui().label]):append_text(")")
    mme_subtree:add(pf_seq_num, buffer(8, 1))

    local mmtype = f_mmtype()()

    if mmtype == MMTYPE_DISCOVER_LIST_REQ then
        mme_subtree:add(pf_sig, buffer(9, 16))
    elseif mmtype == MMTYPE_DISCOVER_LIST_CNF then
        mme_subtree:add_le(pf_interface, buffer(9, 1))
        mme_subtree:add_le(pf_hfid_len, buffer(10, 1))
        mme_subtree:add(pf_hfid, buffer(11, f_hfidlen()()))
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        mme_subtree:add_le(pf_param, buffer(9, 1))
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        mme_subtree:add_le(pf_octets_per_elem, buffer(9, 1))
        mme_subtree:add_le(pf_num_elems, buffer(10, 2))
        local octets_per_elem = f_octets_per_elem()()
        local num_elems = f_num_elems()()
        if length == 76 and octets_per_elem == 1 and num_elems == 64 then
            mme_subtree:add(pf_param_string, buffer(12))
        elseif octets_per_elem == 4 and num_elems == 1 then
            mme_subtree:add_le(pf_param_uint32, buffer(12, 4))
        end
    end
end

local ethertype = DissectorTable.get("ethertype")
ethertype:add(ETHERTYPE_MEDIAXTREAM, mediaxtream_protocol)

