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
local p_mediaxtream = Proto("Mediaxtream",  "Gigle Mediaxtream Protocol")

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

local mmtype_info = {
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

local message_types = {
    [0] = "request",
    [1] = "confirmation",
    [2] = "indication",
    [3] = "response"
}

local pf = {
    mmv             = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC),
    mmtype          = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtype_info),
    fmi             = ProtoField.uint16("mediaxtream.fmi", "Fragmentation Management Information", base.HEX),
    oui             = ProtoField.bytes("mediaxtream.mme.oui", "Organizationally Unique Identifier", base.COLON),
    seq_num         = ProtoField.uint8("mediaxtream.mme.seqNum", "Sequence Number", base.DEC),
    sig             = ProtoField.bytes("mediaxtream.mme.sig", "Signature", base.SPACE),
    interface       = ProtoField.uint8("mediaxtream.mme.interface", "Interface", base.HEX, interfaces),
    hfid_len        = ProtoField.uint8("mediaxtream.mme.hfidLen", "Human-Friendly Identifier Length", base.DEC),
    hfid            = ProtoField.string("mediaxtream.mme.hfid", "Human-Friendly Identifier", base.ASCII),
    paramid         = ProtoField.uint8("mediaxtream.mme.paramid", "Parameter", base.HEX, params),
    octets_per_elem = ProtoField.uint8("mediaxtream.mme.param.octetsPerElem", "Octets per Element", base.DEC),
    num_elems       = ProtoField.uint16("mediaxtream.mme.param.numElems", "Number of Elements", base.DEC),
    param_string    = ProtoField.string("mediaxtream.mme.param.string", "Value", base.ASCII),
    param_uint32    = ProtoField.uint32("mediaxtream.mme.param.uint32", "Value", base.HEX),
    param_bytes     = ProtoField.bytes("mediaxtream.mme.param.bytes", "Value", base.SPACE)
}

p_mediaxtream.fields = pf

local f_mmtype          = Field.new("mediaxtream.mmtype")
local f_oui             = Field.new("mediaxtream.mme.oui")
local f_hfidlen         = Field.new("mediaxtream.mme.hfidLen")
local f_octets_per_elem = Field.new("mediaxtream.mme.param.octetsPerElem")
local f_num_elems       = Field.new("mediaxtream.mme.param.numElems")
local f_param_string    = Field.new("mediaxtream.mme.param.string")
local f_param_uint32    = Field.new("mediaxtream.mme.param.uint32")
local f_param_bytes     = Field.new("mediaxtream.mme.param.bytes")

function p_mediaxtream.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 46 then return end

    pinfo.cols.protocol = p_mediaxtream.name

    local subtree = tree:add(p_mediaxtream, buffer(), "Mediaxtream Protocol")

    subtree:add_le(pf.mmv,    buffer(0,1))
    subtree:add_le(pf.mmtype, buffer(1,2))
    subtree:add_le(pf.fmi,    buffer(3,2))

    local mmtype = f_mmtype()()

    pinfo.cols.info:set(mmtype_info[mmtype])

    subtree:append_text(" (" .. message_types[mmtype % 4] .. ")")

    local mme_subtree = subtree:add(buffer(5), "Management Message Entry")
    mme_subtree:add(pf.oui, buffer(5, 3)):append_text(" (" .. ouis[f_oui().label] .. ")")
    mme_subtree:add(pf.seq_num, buffer(8, 1))

    if mmtype == MMTYPE_DISCOVER_LIST_REQ then
        local item = mme_subtree:add(pf.sig, buffer(9, 16))
        mme_subtree:set_len(4 + item.len)
    elseif mmtype == MMTYPE_DISCOVER_LIST_CNF then
        mme_subtree:add_le(pf.interface, buffer(9, 1))
        mme_subtree:add_le(pf.hfid_len, buffer(10, 1))
        local item = mme_subtree:add(pf.hfid, buffer(11, f_hfidlen()()))
        mme_subtree:set_len(6 + item.len)
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        local item = mme_subtree:add_le(pf.paramid, buffer(9, 1))
        mme_subtree:set_len(4 + item.len)
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        local param_subtree = mme_subtree:add(buffer(9), "Parameter")
        param_subtree:add_le(pf.octets_per_elem, buffer(9, 1))
        param_subtree:add_le(pf.num_elems, buffer(10, 2))
        local octets_per_elem = f_octets_per_elem()()
        local num_elems = f_num_elems()()
        local item
        if length == 76 and octets_per_elem == 1 and num_elems == 64 then
            item = param_subtree:add(pf.param_string, buffer(12))
            param_subtree:append_text(": " .. f_param_string()())
        elseif octets_per_elem == 4 and num_elems == 1 then
            item = param_subtree:add_le(pf.param_uint32, buffer(12, octets_per_elem * num_elems))
            param_subtree:append_text(": " .. f_param_uint32().display)
            param_subtree:set_len(f_octets_per_elem().len + f_num_elems().len + f_param_uint32().len)
        elseif octets_per_elem == 1 and num_elems == 16 then
            item = param_subtree:add(pf.param_bytes, buffer(12, num_elems))
            param_subtree:append_text(": " .. f_param_bytes().display)
            param_subtree:set_len(f_octets_per_elem().len + f_num_elems().len + f_param_bytes().len)
        end
        mme_subtree:set_len(7 + item.len)
    end
end

local ethertype = DissectorTable.get("ethertype")
ethertype:add(ETHERTYPE_MEDIAXTREAM, p_mediaxtream)

