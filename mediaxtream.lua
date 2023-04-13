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
local MMTYPE_STA_INFO_REQ      = 0xa04c
local MMTYPE_STA_INFO_CNF      = 0xa04d
local MMTYPE_FACTORY_RESET_REQ = 0xa054
local MMTYPE_FACTORY_RESET_CNF = 0xa055
local MMTYPE_SET_PARAM_REQ     = 0xa058
local MMTYPE_SET_PARAM_CNF     = 0xa059
local MMTYPE_GET_PARAM_REQ     = 0xa05c
local MMTYPE_GET_PARAM_CNF     = 0xa05d
local MMTYPE_ERROR_CNF         = 0xa069
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
    [MMTYPE_STA_INFO_REQ]      = "Station Info request",
    [MMTYPE_STA_INFO_CNF]      = "Station Info confirmation",
    [MMTYPE_FACTORY_RESET_REQ] = "Factory Reset request",
    [MMTYPE_FACTORY_RESET_CNF] = "Factory Reset confirmation",
    [MMTYPE_SET_PARAM_REQ]     = "Set Parameter request",
    [MMTYPE_SET_PARAM_CNF]     = "Set Parameter confirmation",
    [MMTYPE_GET_PARAM_REQ]     = "Get Parameter request",
    [MMTYPE_GET_PARAM_CNF]     = "Get Parameter confirmation",
    [MMTYPE_ERROR_CNF]         = "Error confirmation",
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

local param_ids = {
    [0x0007] = "Manufacturer NID",
    [0x0008] = "Manufacturer NMK",
    [0x0009] = "Manufacturer DAK part 1 of 4",
    [0x000a] = "Manufacturer DAK part 2 of 4",
    [0x000b] = "Manufacturer DAK part 3 of 4",
    [0x000c] = "Manufacturer DAK part 4 of 4",
    [0x001b] = "Manufacturer STA HFID",
    [0x001c] = "Manufacturer AVLN HFID",
    [0x0023] = "User NID",
    [0x0024] = "User NMK",
    [0x0025] = "User STA HFID",
    [0x0026] = "User AVLN HFID"
}

local mmtype_lsbs = {
    [0] = "request",
    [1] = "confirmation",
    [2] = "indication",
    [3] = "response"
}

local security_levels = {
    [0] = "Simple Connect",
    [1] = "Secure"
}

local pf = {
    mmv             = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC),
    mmtype          = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtype_info),
    mmtype_lsbs     = ProtoField.uint16("mediaxtream.mmtype.lsbs", "Two LSBs", base.HEX, mmtype_lsbs, 0x0003),
    fmi             = ProtoField.uint16("mediaxtream.fmi", "Fragmentation Management Information", base.HEX),
    oui             = ProtoField.bytes("mediaxtream.mme.oui", "Organizationally Unique Identifier", base.COLON),
    seq_num         = ProtoField.uint8("mediaxtream.mme.seqNum", "Sequence Number", base.DEC),
    sig             = ProtoField.bytes("mediaxtream.mme.sig", "Signature", base.SPACE),
    interface       = ProtoField.uint8("mediaxtream.mme.interface", "Interface", base.HEX, interfaces),
    hfid_len        = ProtoField.uint8("mediaxtream.mme.hfidLen", "Human-Friendly Identifier Length", base.DEC),
    hfid            = ProtoField.string("mediaxtream.mme.hfid", "Human-Friendly Identifier", base.ASCII),
    param_id        = ProtoField.uint16("mediaxtream.mme.param_id", "Parameter Id", base.HEX, param_ids),
    octets_per_elem = ProtoField.uint8("mediaxtream.mme.param.octetsPerElem", "Octets per Element", base.DEC),
    num_elems       = ProtoField.uint16("mediaxtream.mme.param.numElems", "Number of Elements", base.DEC),
    param_string    = ProtoField.string("mediaxtream.mme.param.string", "Value", base.ASCII),
    param_uint32    = ProtoField.uint32("mediaxtream.mme.param.uint32", "Value", base.HEX),
    param_uint16    = ProtoField.uint16("mediaxtream.mme.param.uint16", "Value", base.HEX),
    param_uint8     = ProtoField.uint8("mediaxtream.mme.param.uint8", "Value", base.DEC),
    param_bytes     = ProtoField.bytes("mediaxtream.mme.param.bytes", "Value", base.COLON),
    nmk             = ProtoField.bytes("mediaxtream.mme.nmk", "Network Membership Key", base.SPACE),
    unknown         = ProtoField.uint8("mediaxtream.mme.unknown", "Unknown", base.HEX),
    sl              = ProtoField.uint8("mediaxtream.mme.sl", "Security Level", base.HEX, security_levels),
}

p_mediaxtream.fields = pf

local f = {
    mmtype          = Field.new("mediaxtream.mmtype"),
    oui             = Field.new("mediaxtream.mme.oui"),
    hfid_len        = Field.new("mediaxtream.mme.hfidLen"),
    octets_per_elem = Field.new("mediaxtream.mme.param.octetsPerElem"),
    num_elems       = Field.new("mediaxtream.mme.param.numElems"),
    param_string    = Field.new("mediaxtream.mme.param.string"),
    param_uint32    = Field.new("mediaxtream.mme.param.uint32"),
    param_uint16    = Field.new("mediaxtream.mme.param.uint16"),
    param_uint8     = Field.new("mediaxtream.mme.param.uint8"),
    param_bytes     = Field.new("mediaxtream.mme.param.bytes")
}

function p_mediaxtream.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 46 then return end

    pinfo.cols.protocol = p_mediaxtream.name

    local subtree = tree:add(p_mediaxtream, buffer(), "Mediaxtream Protocol")

    subtree:add_le(pf.mmv, buffer(0,1))
    local mmtype_subtree = subtree:add_le(pf.mmtype, buffer(1, 2))
    mmtype_subtree:add_le(pf.mmtype_lsbs, buffer(1, 2))
    subtree:add_le(pf.fmi, buffer(3,2))
    --  TODO decode FMI

    local mmtype = f.mmtype()()

    pinfo.cols.info:set(mmtype_info[mmtype])

    local mme_subtree = subtree:add(buffer(5), "Management Message Entry")
    mme_subtree:add(pf.oui, buffer(5, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
    mme_subtree:add_le(pf.seq_num, buffer(8, 1))

    if mmtype == MMTYPE_DISCOVER_LIST_REQ then
        local item = mme_subtree:add(pf.sig, buffer(9, 16))
        mme_subtree:set_len(4 + item.len)
    elseif mmtype == MMTYPE_DISCOVER_LIST_CNF then
        mme_subtree:add_le(pf.interface, buffer(9, 1))
        mme_subtree:add_le(pf.hfid_len, buffer(10, 1))
        local item = mme_subtree:add(pf.hfid, buffer(11, f.hfid_len()()))
        mme_subtree:set_len(6 + item.len)
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        local item = mme_subtree:add_le(pf.param_id, buffer(9, 2))
        mme_subtree:set_len(4 + item.len)
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        local param_subtree = mme_subtree:add(buffer(9), "Parameter")
        param_subtree:add_le(pf.octets_per_elem, buffer(9, 1))
        param_subtree:add_le(pf.num_elems, buffer(10, 2))
        local octets_per_elem = f.octets_per_elem()()
        local num_elems = f.num_elems()()
        local item
        if num_elems == 1 then
            if octets_per_elem == 4 then
                item = param_subtree:add_le(pf.param_uint32, buffer(12, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint32().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint32().len)
            elseif octets_per_elem == 2 then
                item = param_subtree:add_le(pf.param_uint16, buffer(12, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint16().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint16().len)
            else
                item = param_subtree:add_le(pf.param_uint8, buffer(12, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint8().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint8().len)
            end
        elseif num_elems == 64 and length == num_elems + 12 then
            item = param_subtree:add(pf.param_string, buffer(12))
            param_subtree:append_text(": " .. f.param_string().display)
        else
            item = param_subtree:add(pf.param_bytes, buffer(12, num_elems))
            param_subtree:append_text(": " .. f.param_bytes().display)
            param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_bytes().len)
        end
        --  mme_subtree:set_len(7 + item.len)
        mme_subtree:set_len(4 + param_subtree.len)
    elseif mmtype == MMTYPE_SET_KEY_REQ then
        local item = mme_subtree:add(pf.nmk, buffer(9, 16))
        mme_subtree:add_le(pf.unknown, buffer(25, 1))
        mme_subtree:add_le(pf.sl, buffer(26, 1))
        mme_subtree:set_len(6 + item.len)
    elseif mmtype == MMTYPE_SET_KEY_CNF then
        mme_subtree:set_len(4)
    elseif mmtype == MMTYPE_SET_PARAM_REQ then
        mme_subtree:add_le(pf.param_id, buffer(9, 2))
        local param_subtree = mme_subtree:add(buffer(11), "Parameter")
        param_subtree:add_le(pf.octets_per_elem, buffer(11, 1))
        param_subtree:add_le(pf.num_elems, buffer(12, 2))
        local octets_per_elem = f.octets_per_elem()()
        local num_elems = f.num_elems()()
        if num_elems == 1 then
            if octets_per_elem == 4 then
                item = param_subtree:add_le(pf.param_uint32, buffer(14, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint32().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint32().len)
            elseif octets_per_elem == 2 then
                item = param_subtree:add_le(pf.param_uint16, buffer(14, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint16().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint16().len)
            else
                item = param_subtree:add_le(pf.param_uint8, buffer(14, octets_per_elem))
                param_subtree:append_text(": " .. f.param_uint8().display)
                param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_uint8().len)
            end
        elseif num_elems == 64 and length == num_elems + 14 then
            item = param_subtree:add(pf.param_string, buffer(14))
            param_subtree:append_text(": " .. f.param_string().display)
        else
            item = param_subtree:add(pf.param_bytes, buffer(14, num_elems))
            param_subtree:append_text(": " .. f.param_bytes().display)
            param_subtree:set_len(f.octets_per_elem().len + f.num_elems().len + f.param_bytes().len)
        end
        mme_subtree:set_len(6 + param_subtree.len)
    elseif mmtype == MMTYPE_SET_PARAM_CNF then
        mme_subtree:set_len(4)
    elseif mmtype == MMTYPE_ERROR_CNF then
        --  TODO implement
    end
end

local ethertype = DissectorTable.get("ethertype")
ethertype:add(ETHERTYPE_MEDIAXTREAM, p_mediaxtream)

