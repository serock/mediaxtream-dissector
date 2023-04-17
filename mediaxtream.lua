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
    version = "0.5.0",
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
local MMTYPE_ERROR_IND         = 0x6046
local MMTYPE_DISCOVER_LIST_REQ = 0xa070
local MMTYPE_DISCOVER_LIST_CNF = 0xa071

set_plugin_info(my_info)

local factory_reset_types = {
    [0] = "Manufacturer",
    [1] = "User"
}

local interfaces = {
    [0x00] = "MII0",
    [0x01] = "MII1",
    [0x02] = "PLC",
    [0x03] = "PLC",
    [0x04] = "SDR",
}

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
    [MMTYPE_ERROR_IND]         = "Error indication",
    [MMTYPE_DISCOVER_LIST_REQ] = "Discover List request",
    [MMTYPE_DISCOVER_LIST_CNF] = "Discover List confirmation"
}

local mmtype_lsbs = {
    [0] = "request",
    [1] = "confirmation",
    [2] = "indication",
    [3] = "response"
}

local no_yes = {
    [0] = "no",
    [1] = "yes"
}

local ouis = {
   ["00:1f:84"] = "Gigle Semiconductor"
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

local reason_codes = {
    [0] = "MME not supported",
    [1] = "Supported MME with invalid MME fields",
    [2] = "Unsupported feature"
}

local security_levels = {
    [0] = "Simple Connect",
    [1] = "Secure"
}

local signals = {
    [0] = "SISO1",
    [1] = "SISO2",
    [2] = "MIMO",
    [3] = "SISO only"
}

local specifications = {
    [0] = "HPAV 1.1",
    [1] = "HPAV 2.0",
    [2] = "IEEE 1901",
    [3] = "IEEE 1901"
}

local pf = {
    mmv             = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC),
    mmtype          = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtype_info),
    mmtype_lsbs     = ProtoField.uint16("mediaxtream.mmtype.lsbs", "Two LSBs", base.DEC, mmtype_lsbs, 0x0003),
    fmi             = ProtoField.bytes("mediaxtream.fmi", "Fragmentation Management Information", base.COLON),
    fmi_nf_mi       = ProtoField.uint8("mediaxtream.fmi.nfMi", "Number of Fragments", base.DEC, nil, 0xf0),
    fmi_fn_mi       = ProtoField.uint8("mediaxtream.fmi.fnMi", "Fragment Number", base.DEC, nil, 0x0f),
    fmi_fmsn        = ProtoField.uint8("mediaxtream.fmi.fmsn", "Fragmentation Message Sequence Number", base.DEC),
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
    sec_level       = ProtoField.uint8("mediaxtream.mme.secLvl", "Security Level", base.DEC, security_levels),
    reset           = ProtoField.uint8("mediaxtream.mme.reset", "Factory Reset Type", base.DEC, factory_reset_types),
    nid             = ProtoField.uint64("mediaxtream.mme.nid", "Network Identifier", base.HEX),
    nid_sec_level   = ProtoField.uint8("mediaxtream.mme.nid.secLvl", "Security Level", base.DEC, security_levels, 0x30),
    num_stas        = ProtoField.uint8("mediaxtream.mme.numStas", "Number of Other Stations", base.DEC),
    dest_addr       = ProtoField.ether("mediaxtream.mme.destAddr", "Destination Address (DA)"),
    tx_spec         = ProtoField.uint16("mediaxtream.mme.txSpec", "Transmit Specification", base.DEC, specifications, 0xc000),
    tx_signal       = ProtoField.uint16("mediaxtream.mme.txSignal", "Transmit Signal", base.DEC, signals, 0x3000),
    tx_sb           = ProtoField.uint16("mediaxtream.mme.txSb", "Transmit Spot Beamforming", base.DEC, no_yes, 0x0800),
    tx_rate         = ProtoField.uint16("mediaxtream.mme.txRate", "Transmit Rate to DA", base.DEC, nil, 0x07ff),
    rx_spec         = ProtoField.uint16("mediaxtream.mme.rxSpec", "Receive Specification", base.DEC, specifications, 0xc000),
    rx_signal       = ProtoField.uint16("mediaxtream.mme.rxSignal", "Receive Signal", base.DEC, signals, 0x3000),
    rx_sb           = ProtoField.uint16("mediaxtream.mme.rxSb", "Receive Spot Beamforming", base.DEC, no_yes, 0x0800),
    rx_rate         = ProtoField.uint16("mediaxtream.mme.rxRate", "Receive Rate from DA", base.DEC, nil, 0x07ff),
    reason_code     = ProtoField.uint8("mediaxtream.mme.reasonCode", "Reason Code", base.DEC, reason_codes),
    mx_reason_code  = ProtoField.uint8("mediaxtream.mme.mxReasonCode", "Reason Code", base.DEC),
    rx_mmv          = ProtoField.uint8("mediaxtream.mme.rxMmv", "Received Management Message Version", base.DEC),
    rx_mmtype       = ProtoField.uint8("mediaxtream.mme.rxMmtype", "Received Management Message Type", base.HEX),
    inv_fld_offset  = ProtoField.uint16("mediaxtream.mme.invFldOffset", "Invalid Field Offset", base.DEC)
}

p_mediaxtream.fields = pf

local f = {
    mmtype          = Field.new("mediaxtream.mmtype"),
    oui             = Field.new("mediaxtream.mme.oui"),
    hfid_len        = Field.new("mediaxtream.mme.hfidLen"),
    octets_per_elem = Field.new("mediaxtream.mme.param.octetsPerElem"),
    num_elems       = Field.new("mediaxtream.mme.param.numElems"),
    param_uint32    = Field.new("mediaxtream.mme.param.uint32"),
    param_uint16    = Field.new("mediaxtream.mme.param.uint16"),
    param_uint8     = Field.new("mediaxtream.mme.param.uint8"),
    param_string    = Field.new("mediaxtream.mme.param.string"),
    param_bytes     = Field.new("mediaxtream.mme.param.bytes"),
    num_stas        = Field.new("mediaxtream.mme.numStas"),
    reason_code     = Field.new("mediaxtream.mme.reasonCode")
}

local buffer_len
local mmtype

local function dissect_homeplug_mme(buffer, mme_tree)
    if mmtype == MMTYPE_ERROR_IND then
        mme_tree:add_le(pf.reason_code, buffer(5, 1))
        mme_tree:add_le(pf.rx_mmv, buffer(6, 1))
        mme_tree:add_le(pf.rx_mmtype, buffer(7, 2))
        local mme_len
        local rc = f.reason_code()()
        if rc == 1 then
            mme_tree:add_le(pf.inv_fld_offset, buffer(9, 2))
            mme_len = 6  -- 6=9+2-5
        else
            mme_len = 4  -- 4=7+2-5 
        end
        mme_tree:set_len(mme_len)
    end
end

local function dissect_mediaxtreme_mme(buffer, mme_tree)
    mme_tree:add(pf.oui, buffer(5, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
    mme_tree:add_le(pf.seq_num, buffer(8, 1))

    if mmtype == MMTYPE_DISCOVER_LIST_REQ then
        mme_tree:add(pf.sig, buffer(9, 16))
        mme_tree:set_len(20)  -- 20=9+16-5
    elseif mmtype == MMTYPE_DISCOVER_LIST_CNF then
        mme_tree:add_le(pf.interface, buffer(9, 1))
        mme_tree:add_le(pf.hfid_len, buffer(10, 1))
        local hfid_len = f.hfid_len()()
        mme_tree:add(pf.hfid, buffer(11, hfid_len))
        mme_tree:set_len(6 + hfid_len)  -- 6=11-5
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        mme_tree:add_le(pf.param_id, buffer(9, 2))
        mme_tree:set_len(6)  -- 6=9+2-5
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        local param_tree = mme_tree:add(buffer(9), "Parameter")
        param_tree:add_le(pf.octets_per_elem, buffer(9, 1))
        param_tree:add_le(pf.num_elems, buffer(10, 2))
        local octets_per_elem = f.octets_per_elem()()
        local num_elems = f.num_elems()()
        if num_elems == 1 then
            if octets_per_elem == 4 then
                param_tree:add_le(pf.param_uint32, buffer(12, 4))
                param_tree:set_len(7)  -- 7=12+4-9
                param_tree:append_text(": " .. f.param_uint32().display)
            elseif octets_per_elem == 2 then
                param_tree:add_le(pf.param_uint16, buffer(12, 2))
                param_tree:set_len(5)  -- 5=12+2-9
                param_tree:append_text(": " .. f.param_uint16().display)
            elseif octets_per_elem == 1 then
                param_tree:add_le(pf.param_uint8, buffer(12, 1))
                param_tree:set_len(4)  -- 4=12+1-9
                param_tree:append_text(": " .. f.param_uint8().display)
            end
        elseif num_elems == 64 and buffer_len == 76 then  -- 76=12+64
            param_tree:add(pf.param_string, buffer(12, 64))
            param_tree:set_len(67)  -- 67=12+64-9
            param_tree:append_text(": " .. f.param_string().display)
        else
            param_tree:add(pf.param_bytes, buffer(12, num_elems))
            param_tree:set_len(3 + num_elems)  -- 3=12-9
            param_tree:append_text(": " .. f.param_bytes().display)
        end
        mme_tree:set_len(4 + param_tree.len)  -- 4=8+1-5
    elseif mmtype == MMTYPE_SET_KEY_REQ then
        mme_tree:add(pf.nmk, buffer(9, 16))
        mme_tree:add_le(pf.unknown, buffer(25, 1))
        mme_tree:add_le(pf.sec_level, buffer(26, 1))
        mme_tree:set_len(22)  -- 22=26+1-5
    elseif mmtype == MMTYPE_SET_KEY_CNF then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_SET_PARAM_REQ then
        mme_tree:add_le(pf.param_id, buffer(9, 2))
        local param_tree = mme_tree:add(buffer(11), "Parameter")
        param_tree:add_le(pf.octets_per_elem, buffer(11, 1))
        param_tree:add_le(pf.num_elems, buffer(12, 2))
        local octets_per_elem = f.octets_per_elem()()
        local num_elems = f.num_elems()()
        if num_elems == 1 then
            if octets_per_elem == 4 then
                param_tree:add_le(pf.param_uint32, buffer(14, 4))
                param_tree:set_len(7)  -- 7=14+4-11
                param_tree:append_text(": " .. f.param_uint32().display)
            elseif octets_per_elem == 2 then
                param_tree:add_le(pf.param_uint16, buffer(14, 2))
                param_tree:set_len(5)  -- 5=14+2-11
                param_tree:append_text(": " .. f.param_uint16().display)
            elseif octets_per_elem == 1 then
                param_tree:add_le(pf.param_uint8, buffer(14, 1))
                param_tree:set_len(4)  -- 4=14+1-11
                param_tree:append_text(": " .. f.param_uint8().display)
            end
        elseif num_elems == 64 and buffer_len == 78 then  -- 78=14+64
            param_tree:add(pf.param_string, buffer(14, 64))
            param_tree:set_len(67)  -- 67=14+64-11
            param_tree:append_text(": " .. f.param_string().display)
        else
            param_tree:add(pf.param_bytes, buffer(14, num_elems))
            param_tree:set_len(3 + num_elems)  -- 3=14-11
            param_tree:append_text(": " .. f.param_bytes().display)
        end
        mme_tree:set_len(6 + param_tree.len)  -- 6=9+2-5
    elseif mmtype == MMTYPE_SET_PARAM_CNF then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_STA_RESTART_REQ then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_STA_RESTART_CNF then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_FACTORY_RESET_REQ then
        mme_tree:add_le(pf.reset, buffer(9, 1))
        mme_tree:set_len(5)  -- 5=9+1-5
    elseif mmtype == MMTYPE_FACTORY_RESET_CNF then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_NW_INFO_REQ then
        --  TODO implement
    elseif mmtype == MMTYPE_NW_INFO_CNF then
        --  TODO implement
    elseif mmtype == MMTYPE_NW_STATS_REQ then
        mme_tree:add_le(pf.unknown, buffer(9, 1))
        local nid_tree = mme_tree:add_le(pf.nid, buffer(10, 7))
        nid_tree.text = string.gsub(nid_tree.text, "0x000", "0x0")
        nid_tree:add_le(pf.nid_sec_level, buffer(16, 1))
        mme_tree:set_len(12)  -- 12=10+7-5
    elseif mmtype == MMTYPE_NW_STATS_CNF then
        mme_tree:add_le(pf.num_stas, buffer(9, 1))
        local num_stas = f.num_stas()()
        local i = 10
        for j = 1, num_stas do
            local sta_tree = mme_tree:add(buffer(i, 10), "Station " .. j)
            sta_tree:add(pf.dest_addr, buffer(i, 6))
            sta_tree:add_le(pf.tx_spec, buffer(i + 6, 2))
            sta_tree:add_le(pf.tx_signal, buffer(i + 6, 2))
            sta_tree:add_le(pf.tx_sb, buffer(i + 6, 2))
            sta_tree:add_le(pf.tx_rate, buffer(i + 6, 2)):append_text(" Mbps")
            sta_tree:add_le(pf.rx_spec, buffer(i + 8, 2))
            sta_tree:add_le(pf.rx_signal, buffer(i + 8, 2))
            sta_tree:add_le(pf.rx_sb, buffer(i + 8, 2))
            sta_tree:add_le(pf.rx_rate, buffer(i + 8, 2)):append_text(" Mbps")
            i = i + 10
        end
        mme_tree:set_len(5 + 10 * num_stas)  -- 5=9+1-5
    elseif mmtype == MMTYPE_ERROR_CNF then
        local ti_rc        = mme_tree:add_le(pf.mx_reason_code, buffer(9, 1))
        local ti_rx_mmv    = mme_tree:add_le(pf.rx_mmv, buffer(10, 1))
        local ti_rx_mmtype = mme_tree:add_le(pf.rx_mmtype, buffer(11, 2))
        mme_tree:set_len(8)  -- 8=11+2-5
    end
end

local function update_packet_info(pinfo)
    pinfo.cols.protocol = p_mediaxtream.name

    if mmtype_info[mmtype] ~= nil then
        pinfo.cols.info:set(mmtype_info[mmtype])
    end
end

function p_mediaxtream.dissector(buffer, pinfo, tree)
    buffer_len = buffer:len()
    if buffer_len < 46 then return end

    local mxp_tree = tree:add(p_mediaxtream, buffer(), "Mediaxtream Protocol")

    mxp_tree:add_le(pf.mmv, buffer(0, 1))
    mxp_tree:add_le(pf.mmtype, buffer(1, 2)):add_le(pf.mmtype_lsbs, buffer(1, 2))

    mmtype = f.mmtype()()

    do
        local fmi_tree = mxp_tree:add(pf.fmi, buffer(3, 2))
        fmi_tree:add(pf.fmi_nf_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fn_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fmsn,  buffer(4, 1))
    end

    update_packet_info(pinfo)

    local mme_tree = mxp_tree:add(buffer(5), "Management Message Entry")

    if mmtype >= 0xa000 then
        dissect_mediaxtreme_mme(buffer, mme_tree)
    else
        dissect_homeplug_mme(buffer, mme_tree)
    end
end

local dt_ethertype = DissectorTable.get("ethertype")
dt_ethertype:add(ETHERTYPE_MEDIAXTREAM, p_mediaxtream)
