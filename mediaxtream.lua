--  SPDX-License-Identifier: GPL-2.0-or-later
------------------------------------------------------------------------
--  mediaxtream-dissector - A Mediaxtream protocol dissector for
--                          Wireshark
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
    version = "0.7.0",
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
local MMTYPE_DISCOVER_REQ      = 0xa070
local MMTYPE_DISCOVER_CNF      = 0xa071

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
    [MMTYPE_DISCOVER_REQ]      = "Discover request",
    [MMTYPE_DISCOVER_CNF]      = "Discover confirmation"
}

local mmtype_lsbs = {
    [0] = "request",
    [1] = "confirmation",
    [2] = "indication",
    [3] = "response"
}

local network_kinds = {
    [0] = "In-home",
    [1] = "Access"
}

local networks = {
    [0] = "Member",
    [1] = "All"
}

local nid_kinds = {
    [0] = "Default",
    [1] = "Non-default"
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

local sta_roles = {
    [0] = "Unassociated Station",
    [1] = "Unassociated Central Coordinator",
    [2] = "Station",
    [3] = "Central Coordinator",
    [4] = "Backup Central Coordinator"
}

local sta_status = {
    [0] = "Joined",
    [1] = "Not joined, have Network Membership Key",
    [2] = "Not joined, no Network Membership Key"
}

local pf = {
    mmv                   = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC),
    mmtype                = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtype_info),
    mmtype_lsbs           = ProtoField.uint16("mediaxtream.mmtype.lsbs", "Two LSBs", base.DEC, mmtype_lsbs, 0x0003),
    fmi                   = ProtoField.bytes("mediaxtream.fmi", "Fragmentation Management Information", base.COLON),
    fmi_nf_mi             = ProtoField.uint8("mediaxtream.fmi.nf_mi", "Number of Fragments", base.DEC, nil, 0xf0),
    fmi_fn_mi             = ProtoField.uint8("mediaxtream.fmi.fn_mi", "Fragment Number", base.DEC, nil, 0x0f),
    fmi_fmsn              = ProtoField.uint8("mediaxtream.fmi.fmsn", "Fragmentation Message Sequence Number", base.DEC),
    oui                   = ProtoField.bytes("mediaxtream.oui", "Organizationally Unique Identifier", base.COLON),
    seq_num               = ProtoField.uint8("mediaxtream.seq_num", "Sequence Number", base.DEC),
    signature             = ProtoField.bytes("mediaxtream.signature", "Signature", base.SPACE),
    interface             = ProtoField.uint8("mediaxtream.interface", "Interface", base.DEC, interfaces),
    hfid_len              = ProtoField.uint8("mediaxtream.hfid_len", "Human-Friendly Identifier Length", base.DEC),
    hfid                  = ProtoField.string("mediaxtream.hfid", "Human-Friendly Identifier", base.ASCII),
    param_id              = ProtoField.uint16("mediaxtream.param_id", "Parameter Id", base.HEX, param_ids),
    octets_per_elem       = ProtoField.uint8("mediaxtream.param.octets_per_elem", "Octets per Element", base.DEC),
    num_elems             = ProtoField.uint16("mediaxtream.param.num_elems", "Number of Elements", base.DEC),
    param_string          = ProtoField.string("mediaxtream.param.string", "Value", base.ASCII),
    param_nid             = ProtoField.uint64("mediaxtream.param.nid", "Value", base.HEX),
    param_nid_sl          = ProtoField.uint8("mediaxtream.param.nid.sl", "Security Level", base.DEC, security_levels, 0x30),
    param_uint32          = ProtoField.uint32("mediaxtream.param.uint32", "Value", base.HEX),
    param_uint16          = ProtoField.uint16("mediaxtream.param.uint16", "Value", base.HEX),
    param_uint8           = ProtoField.uint8("mediaxtream.param.uint8", "Value", base.DEC),
    param_bytes           = ProtoField.bytes("mediaxtream.param.bytes", "Value", base.COLON),
    nmk                   = ProtoField.bytes("mediaxtream.nmk", "Network Membership Key", base.SPACE),
    nid_kind              = ProtoField.uint8("mediaxtream.nid_kind", "NID Type", base.DEC, nid_kinds),
    security_level        = ProtoField.uint8("mediaxtream.sl", "Security Level", base.DEC, security_levels),
    reset                 = ProtoField.uint8("mediaxtream.reset", "Factory Reset Type", base.DEC, factory_reset_types),
    nid                   = ProtoField.uint64("mediaxtream.nid", "Network Identifier", base.HEX),
    nid_sl                = ProtoField.uint8("mediaxtream.nid.sl", "Security Level", base.DEC, security_levels, 0x30),
    num_stas              = ProtoField.uint8("mediaxtream.num_stas", "Number of Other Stations", base.DEC),
    sta_dest_addr         = ProtoField.ether("mediaxtream.sta.dest_addr", "Destination Address (DA)"),
    sta_tx_spec           = ProtoField.uint16("mediaxtream.sta.tx_spec", "Transmit Specification", base.DEC, specifications, 0xc000),
    sta_tx_signal         = ProtoField.uint16("mediaxtream.sta.tx_signal", "Transmit Signal", base.DEC, signals, 0x3000),
    sta_tx_sb             = ProtoField.uint16("mediaxtream.sta.tx_sb", "Transmit Spot Beamforming", base.DEC, no_yes, 0x0800),
    sta_tx_rate           = ProtoField.uint16("mediaxtream.sta.tx_rate", "Transmit Rate to DA", base.DEC, nil, 0x07ff),
    sta_rx_spec           = ProtoField.uint16("mediaxtream.sta.rx_spec", "Receive Specification", base.DEC, specifications, 0xc000),
    sta_rx_signal         = ProtoField.uint16("mediaxtream.sta.rx_signal", "Receive Signal", base.DEC, signals, 0x3000),
    sta_rx_sb             = ProtoField.uint16("mediaxtream.sta.rx_sb", "Receive Spot Beamforming", base.DEC, no_yes, 0x0800),
    sta_rx_rate           = ProtoField.uint16("mediaxtream.sta.rx_rate", "Receive Rate from DA", base.DEC, nil, 0x07ff),
    reason_code           = ProtoField.uint8("mediaxtream.rc", "Reason Code", base.DEC, reason_codes),
    vendor_reason_code    = ProtoField.uint8("mediaxtream.vendor_rc", "Reason Code", base.DEC),
    rx_mmv                = ProtoField.uint8("mediaxtream.rx_mmv", "Received Management Message Version", base.DEC),
    rx_mmtype             = ProtoField.uint8("mediaxtream.rx_mmtype", "Received Management Message Type", base.HEX),
    invalid_field_offset  = ProtoField.uint16("mediaxtream.invalid_field_offset", "Invalid Field Offset", base.DEC),
    unknown               = ProtoField.uint8("mediaxtream.unknown", "Unknown", base.DEC),
    network_scope         = ProtoField.uint8("mediaxtream.network_scope", "Network Scope", base.DEC, networks),
    num_avlns             = ProtoField.uint8("mediaxtream.num_avlns", "Number of HomePlug AV Logical Networks", base.DEC),
    nw_nid                = ProtoField.uint64("mediaxtream.nw.nid", "Network Identifier", base.HEX),
    nw_nid_sl             = ProtoField.uint8("mediaxtream.nid.sl", "Security Level", base.DEC, security_levels, 0x30),
    nw_snid               = ProtoField.uint8("mediaxtream.nw.snid", "Short Network Identifier", base.DEC),
    nw_tei                = ProtoField.uint8("mediaxtream.nw.tei", "Terminal Equipment Identifier of Station", base.DEC),
    nw_sta_role           = ProtoField.uint8("mediaxtream.nw.sta_role", "Station Role", base.DEC, sta_roles),
    nw_cco_addr           = ProtoField.ether("mediaxtream.nw.cco_addr", "Central Coordinator"),
    nw_network_kind       = ProtoField.uint8("mediaxtream.nw.network_kind", "Network Type", base.DEC, network_kinds),
    nw_num_coord_networks = ProtoField.uint8("mediaxtream.nw.num_coord_networks", "Number of Coordinating Networks", base.DEC),
    nw_sta_status         = ProtoField.uint8("mediaxtream.nw.sta_status", "Station Status in Network", base.DEC, sta_status),
    bcco_addr             = ProtoField.ether("mediaxtream.bcco_addr", "Backup Central Coordinator")
}

local ef = {
    invalid_mmv    = ProtoExpert.new("mediaxtream.invalid_mmv.expert", "Invalid Management Message Version", expert.group.PROTOCOL, expert.severity.ERROR),
    unexpected_mmv = ProtoExpert.new("mediaxtream.unrecognized_mmv.expert", "Unexpected Management Message Version", expert.group.UNDECODED, expert.severity.WARN)
}

p_mediaxtream.fields  = pf
p_mediaxtream.experts = ef

local f = {
    mmv             = Field.new("mediaxtream.mmv"),
    mmtype          = Field.new("mediaxtream.mmtype"),
    oui             = Field.new("mediaxtream.oui"),
    hfid_len        = Field.new("mediaxtream.hfid_len"),
    octets_per_elem = Field.new("mediaxtream.param.octets_per_elem"),
    num_elems       = Field.new("mediaxtream.param.num_elems"),
    param_string    = Field.new("mediaxtream.param.string"),
    param_nid       = Field.new("mediaxtream.param.nid"),
    param_uint32    = Field.new("mediaxtream.param.uint32"),
    param_uint16    = Field.new("mediaxtream.param.uint16"),
    param_uint8     = Field.new("mediaxtream.param.uint8"),
    param_bytes     = Field.new("mediaxtream.param.bytes"),
    nid_kind        = Field.new("mediaxtream.nid_kind"),
    num_stas        = Field.new("mediaxtream.num_stas"),
    reason_code     = Field.new("mediaxtream.rc"),
    num_avlns       = Field.new("mediaxtream.num_avlns")
}

local buffer_len
local mmtype
local mmv

local function dissect_error_ind(buffer, mme_tree)
    mme_tree:add_le(pf.reason_code, buffer(5, 1))
    mme_tree:add_le(pf.rx_mmv, buffer(6, 1))
    mme_tree:add_le(pf.rx_mmtype, buffer(7, 2))
    local mme_len
    local rc = f.reason_code()()
    if rc == 1 then
        mme_tree:add_le(pf.invalid_field_offset, buffer(9, 2))
        mme_len = 6  -- 6=9+2-5
    else
        mme_len = 4  -- 4=7+2-5 
    end
    mme_tree:set_len(mme_len)
end

local function dissect_get_param_cnf(buffer, mme_tree)
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
    elseif num_elems == 7 then
        local value_tree = param_tree:add_le(pf.param_nid, buffer(12, 7))
        param_tree:set_len(10)  -- 10=12+7-9
        value_tree.text = string.gsub(value_tree.text, "0x00", "0x")
        value_tree:add_le(pf.param_nid_sl, buffer(18, 1))
        param_tree:append_text(": " .. f.param_nid().display)
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
end

local function dissect_nw_info_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.num_avlns, buffer(9, 1))
    local num_avlns = f.num_avlns()()
    local i = 10
    for j = 1, num_avlns do
        local avln_tree = mme_tree:add(buffer(i, 19), "Network " .. j)
        local nid_tree  = avln_tree:add_le(pf.nw_nid, buffer(i, 7))
        nid_tree.text = string.gsub(nid_tree.text, "0x00", "0x")
        nid_tree:add_le(pf.nw_nid_sl, buffer(i + 6, 1))
        avln_tree:add_le(pf.nw_snid, buffer(i + 7, 1))
        avln_tree:add_le(pf.nw_tei, buffer(i + 8, 1))
        avln_tree:add_le(pf.nw_sta_role, buffer(i + 9, 1))
        avln_tree:add(pf.nw_cco_addr, buffer(i + 10, 6))
        avln_tree:add(pf.nw_network_kind, buffer(i + 16, 1))
        avln_tree:add(pf.nw_num_coord_networks, buffer(i + 17, 1))
        avln_tree:add(pf.nw_sta_status, buffer(i + 18, 1))
        i = i + 19
    end
    for j = 1, num_avlns do
        mme_tree:add(pf.bcco_addr, buffer(i, 6)):prepend_text("Network " .. j .. " ")
        i = i + 6
    end
    mme_tree:set_len(i - 5)
end

local function dissect_nw_stats_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.num_stas, buffer(9, 1))
    local num_stas = f.num_stas()()
    local i = 10
    for j = 1, num_stas do
        local sta_tree = mme_tree:add(buffer(i, 10), "Station " .. j)
        sta_tree:add(pf.sta_dest_addr, buffer(i, 6))
        sta_tree:add_le(pf.sta_tx_spec, buffer(i + 6, 2))
        sta_tree:add_le(pf.sta_tx_signal, buffer(i + 6, 2))
        sta_tree:add_le(pf.sta_tx_sb, buffer(i + 6, 2))
        sta_tree:add_le(pf.sta_tx_rate, buffer(i + 6, 2)):append_text(" Mbps")
        sta_tree:add_le(pf.sta_rx_spec, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_signal, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_sb, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_rate, buffer(i + 8, 2)):append_text(" Mbps")
        i = i + 10
    end
    mme_tree:set_len(5 + 10 * num_stas)  -- 5=9+1-5
end

local function dissect_set_param_req(buffer, mme_tree)
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
    elseif num_elems == 7 then
        local value_tree = param_tree:add_le(pf.param_nid, buffer(14, 7))
        param_tree:set_len(10)  -- 10=14+7-11
        value_tree.text = string.gsub(value_tree.text, "0x00", "0x")
        value_tree:add_le(pf.param_nid_sl, buffer(20, 1))
        param_tree:append_text(": " .. f.param_nid().display)
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
end

local function dissect_mediaxtreme_mme(buffer, mme_tree)
    if mmtype >= 0xa000 then
        mme_tree:add(pf.oui, buffer(5, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
        mme_tree:add_le(pf.seq_num, buffer(8, 1))
    end

    if mmtype == MMTYPE_DISCOVER_REQ then
        if mmv == 1 then
            mme_tree:add(pf.signature, buffer(9, 16))
            mme_tree:set_len(20)  -- 20=9+16-5
        else
           mme_tree:add_proto_expert_info(ef.unexpected_mmv)
        end
    elseif mmtype == MMTYPE_DISCOVER_CNF then
        if mmv == 2 then
            mme_tree:add_le(pf.interface, buffer(9, 1))
            mme_tree:add_le(pf.hfid_len, buffer(10, 1))
            local hfid_len = f.hfid_len()()
            mme_tree:add(pf.hfid, buffer(11, hfid_len))
            mme_tree:set_len(6 + hfid_len)  -- 6=11-5
        else
           mme_tree:add_proto_expert_info(ef.unexpected_mmv)
        end
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        mme_tree:add_le(pf.param_id, buffer(9, 2))
        mme_tree:set_len(6)  -- 6=9+2-5
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        dissect_get_param_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_SET_KEY_REQ then
        mme_tree:add(pf.nmk, buffer(9, 16))
        mme_tree:add_le(pf.nid_kind, buffer(25, 1))
        local nid_kind = f.nid_kind()()
        if nid_kind == 0 then
            mme_tree:add_le(pf.security_level, buffer(26, 1))
            mme_tree:set_len(22)  -- 22=26+1-5
        elseif nid_kind == 1 then
            -- TODO dissect NID, SL, and next 16 bytes
        end
    elseif mmtype == MMTYPE_SET_KEY_CNF then
        mme_tree:set_len(4)  -- 4=8+1-5
    elseif mmtype == MMTYPE_SET_PARAM_REQ then
        dissect_set_param_req(buffer, mme_tree)
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
        mme_tree:add_le(pf.unknown, buffer(9, 1))
        mme_tree:add_le(pf.network_scope, buffer(10, 1))
        mme_tree:set_len(6)  -- 6=10+1-5
    elseif mmtype == MMTYPE_NW_INFO_CNF then
        dissect_nw_info_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_NW_STATS_REQ then
        mme_tree:add_le(pf.unknown, buffer(9, 1))
        local nid_tree = mme_tree:add_le(pf.nid, buffer(10, 7))
        nid_tree.text = string.gsub(nid_tree.text, "0x00", "0x")
        nid_tree:add_le(pf.nid_sl, buffer(16, 1))
        mme_tree:set_len(12)  -- 12=10+7-5
    elseif mmtype == MMTYPE_NW_STATS_CNF then
        dissect_nw_stats_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_ERROR_CNF then
        local ti_rc        = mme_tree:add_le(pf.vendor_reason_code, buffer(9, 1))
        local ti_rx_mmv    = mme_tree:add_le(pf.rx_mmv, buffer(10, 1))
        local ti_rx_mmtype = mme_tree:add_le(pf.rx_mmtype, buffer(11, 2))
        mme_tree:set_len(8)  -- 8=11+2-5
    elseif mmtype == MMTYPE_ERROR_IND then
        dissect_error_ind(buffer, mme_tree)
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

    local protocol_tree = tree:add(p_mediaxtream, buffer(), "Mediaxtream Protocol")

    protocol_tree:add_le(pf.mmv, buffer(0, 1))
    protocol_tree:add_le(pf.mmtype, buffer(1, 2)):add_le(pf.mmtype_lsbs, buffer(1, 2))

    mmtype = f.mmtype()()
    mmv    = f.mmv()()

    if mmv > 2 then
        protocol_tree:add_proto_expert_info(ef.invalid_mmv)
        return
    end

    do
        local fmi_tree = protocol_tree:add(pf.fmi, buffer(3, 2))
        fmi_tree:add(pf.fmi_nf_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fn_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fmsn,  buffer(4, 1))
    end

    update_packet_info(pinfo)

    local mme_tree = protocol_tree:add(buffer(5), "Management Message Entry")

    dissect_mediaxtreme_mme(buffer, mme_tree)
end

local dt_ethertype = DissectorTable.get("ethertype")
dt_ethertype:add(ETHERTYPE_MEDIAXTREAM, p_mediaxtream)
