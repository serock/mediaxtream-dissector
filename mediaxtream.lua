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

local MMTYPE_AUTHORIZE_REQ     = 0xa010
local MMTYPE_AUTHORIZE_CNF     = 0xa011
local MMTYPE_AUTHORIZE_IND     = 0xa012
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

local authorize_cnf_status = {
    [0] = "Complete",
    [1] = "No response",
    [2] = "Protocol aborted",
    [3] = "Started",
    [4] = "Busy",
    [5] = "Failed"
}

local authorize_ind_status = {
    [0] = "Complete",
    [1] = "Protocol aborted"
}

local authorize_modes = {
    [0] = "Current NMK",
    [2] = "User-provided NMK"
}

local chip_versions = {
    [0x017f0000] = "BCM60500_A0",
    [0x017f024e] = "BCM60500_A1",
    [0x117f024e] = "BCM60500_B0",
    [0x017f024f] = "BCM60333_A1",
    [0x117f024f] = "BCM60333_B0",
    [0x017f025a] = "BCM60335_A0"
}

local factory_reset_types = {
    [0] = "Manufacturer",
    [1] = "User"
}

local firmware_names = {
    [0] = "CONCORDE",
    [1] = "INVALID",
    [2] = "INVALID",
    [3] = "INVALID",
    [4] = "INVALID",
    [5] = "GEMINI",
    [6] = "APOLLO",
    [7] = "HYDRA",
}

local flash_models = {
    [0x00000000] = "UNKNOWN",
    [0x00000001] = "DEFAULT",
    [0x00014015] = "S25FL216K",
    [0x001c3114] = "EN25F80",
    [0x00bf2541] = "SST25VF016B",
    [0x00bf254a] = "SST25VF032B",
    [0x00bf258e] = "SST25VF080B",
    [0x00c22014] = "MX25L8006E",
    [0x00c22015] = "MX25L1606E",
    [0x00c22016] = "MX25L3206E",
    [0x00c84014] = "GD25Q80B",
    [0x00c84015] = "GD25Q16B",
    [0x00c84016] = "GD25Q32B",
    [0x00ef4014] = "W25Q80BV",
    [0x00ef4015] = "W25Q16BV",
    [0x00ef4016] = "W25Q32BV",
    [0x00f83215] = "FM25S16"
}

local homeplug_versions = {
    [0] = "1.1",
    [1] = "2.0"
}

local interfaces = {
    [0x00] = "MII0",
    [0x01] = "MII1",
    [0x02] = "PLC",
    [0x03] = "PLC",
    [0x04] = "SDR",
}

local max_bit_rates = {
    [0] = 200,
    [1] = 1000,
    [2] = 1800
}

local mmtypes = {
    [MMTYPE_AUTHORIZE_REQ]     = "Authorize request",
    [MMTYPE_AUTHORIZE_CNF]     = "Authorize confirmation",
    [MMTYPE_AUTHORIZE_IND]     = "Authorize indication",
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

local rate_units = {
    " Mbps"
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

local ucodes_8 = {
    [1] = "LB_SC",
    [2] = "HB_SC",
    [3] = "LB_FCI",
    [4] = "HB_FCI",
    [5] = "LB_AGC",
    [6] = "HB_AGC",
    [7] = "RX_REC",
    [8] = "TX_FEC"
}

local ucodes_10 = {
    [1] = "SC",
    [2] = "AGC",
    [3] = "FCI",
    [4] = "TX_FEC",
    [5] = "RX_FEC",
    [6] = "SP",
    [7] = "BLK",
    [8] = "DBLK",
    [9] = "PREC",
    [10] = "PREC2"
}

local uptime_units = {
    " seconds"
}

local pf = {
    mmv                   = ProtoField.uint8("mediaxtream.mmv", "Management Message Version", base.DEC),
    mmtype                = ProtoField.uint16("mediaxtream.mmtype", "Management Message Type", base.HEX, mmtypes),
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
    param_bytes           = ProtoField.bytes("mediaxtream.param.bytes", "Value", base.SPACE),
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
    sta_tx_rate           = ProtoField.uint16("mediaxtream.sta.tx_rate", "Transmit Rate to DA", base.UNIT_STRING, rate_units, 0x07ff),
    sta_rx_spec           = ProtoField.uint16("mediaxtream.sta.rx_spec", "Receive Specification", base.DEC, specifications, 0xc000),
    sta_rx_signal         = ProtoField.uint16("mediaxtream.sta.rx_signal", "Receive Signal", base.DEC, signals, 0x3000),
    sta_rx_sb             = ProtoField.uint16("mediaxtream.sta.rx_sb", "Receive Spot Beamforming", base.DEC, no_yes, 0x0800),
    sta_rx_rate           = ProtoField.uint16("mediaxtream.sta.rx_rate", "Receive Rate from DA", base.UNIT_STRING, rate_units, 0x07ff),
    reason_code           = ProtoField.uint8("mediaxtream.rc", "Reason Code", base.DEC, reason_codes),
    vendor_reason_code    = ProtoField.uint8("mediaxtream.vendor_rc", "Reason Code", base.DEC),
    rx_mmv                = ProtoField.uint8("mediaxtream.rx_mmv", "Received Management Message Version", base.DEC),
    rx_mmtype             = ProtoField.uint8("mediaxtream.rx_mmtype", "Received Management Message Type", base.HEX),
    invalid_field_offset  = ProtoField.uint16("mediaxtream.invalid_field_offset", "Invalid Field Offset", base.DEC),
    unknown               = ProtoField.uint8("mediaxtream.unknown", "Unknown", base.DEC),
    network_scope         = ProtoField.uint8("mediaxtream.network_scope", "Network Scope", base.DEC, networks),
    num_avlns             = ProtoField.uint8("mediaxtream.num_avlns", "Number of HomePlug AV Logical Networks", base.DEC),
    nw_nid                = ProtoField.uint64("mediaxtream.nw.nid", "Network Identifier", base.HEX),
    nw_nid_sl             = ProtoField.uint8("mediaxtream.nw.nid.sl", "Security Level", base.DEC, security_levels, 0x30),
    nw_snid               = ProtoField.uint8("mediaxtream.nw.snid", "Short Network Identifier", base.DEC),
    nw_tei                = ProtoField.uint8("mediaxtream.nw.tei", "Terminal Equipment Identifier of Station", base.DEC),
    nw_sta_role           = ProtoField.uint8("mediaxtream.nw.sta_role", "Station Role", base.DEC, sta_roles),
    nw_cco_addr           = ProtoField.ether("mediaxtream.nw.cco_addr", "Central Coordinator"),
    nw_network_kind       = ProtoField.uint8("mediaxtream.nw.network_kind", "Network Type", base.DEC, network_kinds),
    nw_num_coord_networks = ProtoField.uint8("mediaxtream.nw.num_coord_networks", "Number of Coordinating Networks", base.DEC),
    nw_sta_status         = ProtoField.uint8("mediaxtream.nw.sta_status", "Station Status in Network", base.DEC, sta_status),
    bcco_addr             = ProtoField.ether("mediaxtream.bcco_addr", "Backup Central Coordinator"),
    chip_version          = ProtoField.uint32("mediaxtream.chip_ver", "Chip Version", base.HEX, chip_versions),
    hardware_version      = ProtoField.uint32("mediaxtream.hw_ver", "Hardware Version", base.HEX),
    firmware_version_svn  = ProtoField.uint32("mediaxtream.fw_ver_svn", "Firmware Version (svn)", base.DEC),
    chip_full_id          = ProtoField.uint32("mediaxtream.chip_full_id", "Chip Full ID", base.HEX),
    rom_version_major     = ProtoField.uint16("mediaxtream.rom_version.major", "Major", base.DEC, nil, 0xf000),
    rom_version_minor     = ProtoField.uint16("mediaxtream.rom_version.minor", "Minor", base.DEC, nil, 0x0fc0),
    rom_version_build     = ProtoField.uint16("mediaxtream.rom_version.build", "Build", base.DEC, nil, 0x003f),
    param_config_bi_ver   = ProtoField.uint32("mediaxtream.param_config_bi_ver", "Param Config Built-In Version", base.DEC),
    param_config_nvm_ver  = ProtoField.uint32("mediaxtream.param_config_nvm_ver", "Param Config NVM Version", base.DEC),
    num_ucode_elems       = ProtoField.uint8("mediaxtream.num_ucode_elems", "Number of uCodes", base.DEC),
    ucode_name            = ProtoField.string("mediaxtream.ucode_name", "Name", base.ASCII),
    ucode_modified        = ProtoField.uint8("mediaxtream.ucode_modified", "Modified", base.DEC, no_yes),
    ucode_version         = ProtoField.uint32("mediaxtream.ucode_version", "Version", base.DEC),
    uptime                = ProtoField.uint32("mediaxtream.uptime", "Uptime", base.UNIT_STRING, uptime_units),
    fw_boot_msg_len       = ProtoField.uint8("mediaxtream.fw_boot_msg_len", "Firmware Boot Message Length", base.DEC),
    fw_boot_msg           = ProtoField.string("mediaxtream.fw_boot_msg", "Value", base.ASCII),
    fw_version_name       = ProtoField.uint32("mediaxtream.fw_ver.name", "Name", base.DEC, firmware_names, 0x07000000),
    fw_version_major      = ProtoField.uint32("mediaxtream.fw_ver.major", "Major", base.DEC, nil, 0x00ff0000),
    fw_version_minor      = ProtoField.uint32("mediaxtream.fw_ver.minor", "Minor", base.DEC, nil, 0x0000ff00),
    fw_version_build      = ProtoField.uint32("mediaxtream.fw_ver.build", "Build", base.DEC, nil, 0x000000ff),
    firmware_features     = ProtoField.uint32("mediaxtream.firmware_features", "Firmware Features", base.HEX),
    flash_model           = ProtoField.uint32("mediaxtream.flash_model", "Flash Model", base.HEX, flash_models),
    homeplug_version      = ProtoField.uint8("mediaxtream.homeplug_version", "HomePlug Version", base.DEC, homeplug_versions),
    max_bit_rate          = ProtoField.string("mediaxtream.max_bit_rate", "Maximum Bit Rate", base.ASCII),
    dak                   = ProtoField.bytes("mediaxtream.dak", "Device Access Key", base.SPACE),
    authz_mode            = ProtoField.uint8("mediaxtream.authz_mode", "Authorization Mode", base.DEC, authorize_modes),
    authz_cnf_status      = ProtoField.uint8("mediaxtream.authz_cnf_status", "Authorize Status", base.DEC, authorize_cnf_status),
    authz_ind_status      = ProtoField.uint8("mediaxtream.authz_ind_status", "Authorize Status", base.DEC, authorize_ind_status)
}

local ef = {
    invalid_authz_req     = ProtoExpert.new("mediaxtream.invalid_authz_req.expert", "Invalid Authorize Request", expert.group.MALFORMED, expert.severity.ERROR),
    invalid_mmv           = ProtoExpert.new("mediaxtream.invalid_mmv.expert", "Invalid Management Message Version", expert.group.MALFORMED, expert.severity.ERROR),
    unexpected_mmv        = ProtoExpert.new("mediaxtream.unexpected_mmv.expert", "Unexpected Management Message Version", expert.group.UNDECODED, expert.severity.ERROR),
    unexpected_mmv_mmtype = ProtoExpert.new("homeplugav.unexpected_mmv_mmtype.expert", "Unexpected Management Message Version and Type", expert.group.UNDECODED, expert.severity.ERROR),
    unknown_data          = ProtoExpert.new("mediaxtream.unknown_data.expert", "Unknown Data", expert.group.UNDECODED, expert.severity.WARN),
    unknown_mmtype        = ProtoExpert.new("mediaxtream.unknown_data.expert", "Unknown Management Message Type", expert.group.UNDECODED, expert.severity.ERROR)
}

p_mediaxtream.fields  = pf
p_mediaxtream.experts = ef

local f = {
    mmv               = Field.new("mediaxtream.mmv"),
    mmtype            = Field.new("mediaxtream.mmtype"),
    oui               = Field.new("mediaxtream.oui"),
    hfid_len          = Field.new("mediaxtream.hfid_len"),
    octets_per_elem   = Field.new("mediaxtream.param.octets_per_elem"),
    num_elems         = Field.new("mediaxtream.param.num_elems"),
    param_string      = Field.new("mediaxtream.param.string"),
    param_nid         = Field.new("mediaxtream.param.nid"),
    param_uint32      = Field.new("mediaxtream.param.uint32"),
    param_uint16      = Field.new("mediaxtream.param.uint16"),
    param_uint8       = Field.new("mediaxtream.param.uint8"),
    param_bytes       = Field.new("mediaxtream.param.bytes"),
    nid_kind          = Field.new("mediaxtream.nid_kind"),
    num_stas          = Field.new("mediaxtream.num_stas"),
    reason_code       = Field.new("mediaxtream.rc"),
    num_avlns         = Field.new("mediaxtream.num_avlns"),
    rom_version_major = Field.new("mediaxtream.rom_version.major"),
    rom_version_minor = Field.new("mediaxtream.rom_version.minor"),
    rom_version_build = Field.new("mediaxtream.rom_version.build"),
    num_ucode_elems   = Field.new("mediaxtream.num_ucode_elems"),
    fw_boot_msg_len   = Field.new("mediaxtream.fw_boot_msg_len"),
    fw_boot_msg       = Field.new("mediaxtream.fw_boot_msg"),
    fw_version_name   = Field.new("mediaxtream.fw_ver.name"),
    fw_version_major  = Field.new("mediaxtream.fw_ver.major"),
    fw_version_minor  = Field.new("mediaxtream.fw_ver.minor"),
    fw_version_build  = Field.new("mediaxtream.fw_ver.build"),
    authz_mode        = Field.new("mediaxtream.authz_mode"),
}

local buffer_len
local mmtype
local mmv

local function to_firmware_version_string(range)
    local fw_version_name  = f.fw_version_name()()
    local fw_version_major = f.fw_version_major()()
    local fw_version_minor = f.fw_version_minor()()
    local fw_version_build = f.fw_version_build()()
    local result = firmware_names[fw_version_name] .. " " .. fw_version_major .. "." .. fw_version_minor .. "." .. fw_version_build
    return result
end

local function to_max_bit_rate_string(range)
    local value = range:le_uint()
    local result = max_bit_rates[value] .. " Mbps"
    return result
end

local function dissect_authorize_req(buffer, mme_tree)
    mme_tree:add(pf.dak, buffer(9, 16))
    mme_tree:add(pf.sta_dest_addr, buffer(25, 6))
    mme_tree:add(pf.authz_mode, buffer(31, 1))
    local authz_mode = f.authz_mode()()
    if authz_mode == 2 and buffer_len == 49 then
        mme_tree:add(pf.nmk, buffer(32, 16))
        mme_tree:add(pf.security_level, buffer(48, 1))
    elseif authz_mode == 0 then
        mme_tree:add(pf.security_level, buffer(32, 1))
        mme_tree:set_len(28)  -- 28=32+1-5
    else
        mme_tree:add_proto_expert_info(ef.unknown_data)
    end
end

local function dissect_authorize_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.authz_cnf_status, buffer(9, 1))
    mme_tree:set_len(5)  -- 5=9+1-5
end

local function dissect_authorize_ind(buffer, mme_tree)
    mme_tree:add_le(pf.authz_ind_status, buffer(9, 1))
    mme_tree:set_len(5)  -- 5=9+1-5
end

local function dissect_discover_req(buffer, mme_tree)
    mme_tree:add(pf.signature, buffer(9, 16))
    mme_tree:set_len(20)  -- 20=9+16-5
end

local function dissect_discover_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.interface, buffer(9, 1))
    mme_tree:add_le(pf.hfid_len, buffer(10, 1))
    local hfid_len = f.hfid_len()()
    mme_tree:add(pf.hfid, buffer(11, hfid_len))
    mme_tree:set_len(6 + hfid_len)  -- 6=11-5
end

local function dissect_error_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.vendor_reason_code, buffer(9, 1))
    mme_tree:add_le(pf.rx_mmv, buffer(10, 1))
    mme_tree:add_le(pf.rx_mmtype, buffer(11, 2))
    mme_tree:set_len(8)  -- 8=11+2-5
end

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

local function dissect_factory_reset_req(buffer, mme_tree)
    mme_tree:add_le(pf.reset, buffer(9, 1))
    mme_tree:set_len(5)  -- 5=9+1-5
end

local function dissect_factory_reset_cnf(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_get_param_req(buffer, mme_tree)
    mme_tree:add_le(pf.param_id, buffer(9, 2))
    mme_tree:set_len(6)  -- 6=9+2-5
end

local function dissect_get_param_cnf(buffer, mme_tree)
    local param_tree = mme_tree:add(buffer(9), "Parameter: ")
    param_tree:add_le(pf.octets_per_elem, buffer(9, 1))
    param_tree:add_le(pf.num_elems, buffer(10, 2))
    local octets_per_elem = f.octets_per_elem()()
    local num_elems = f.num_elems()()
    if num_elems == 1 then
        if octets_per_elem == 4 then
            param_tree:add_le(pf.param_uint32, buffer(12, 4))
            param_tree:set_len(7)  -- 7=12+4-9
            param_tree:append_text(f.param_uint32().display)
        elseif octets_per_elem == 2 then
            param_tree:add_le(pf.param_uint16, buffer(12, 2))
            param_tree:set_len(5)  -- 5=12+2-9
            param_tree:append_text(f.param_uint16().display)
        elseif octets_per_elem == 1 then
            param_tree:add_le(pf.param_uint8, buffer(12, 1))
            param_tree:set_len(4)  -- 4=12+1-9
            param_tree:append_text(f.param_uint8().display)
        end
    elseif num_elems == 7 then
        local value_tree = param_tree:add_le(pf.param_nid, buffer(12, 7))
        param_tree:set_len(10)  -- 10=12+7-9
        value_tree.text = string.gsub(value_tree.text, "0x00", "0x")
        value_tree:add_le(pf.param_nid_sl, buffer(18, 1))
        param_tree:append_text(f.param_nid().display)
    elseif num_elems == 64 and buffer_len == 76 then  -- 76=12+64
        param_tree:add(pf.param_string, buffer(12, 64))
        param_tree:set_len(67)  -- 67=12+64-9
        param_tree:append_text(f.param_string().display)
    else
        param_tree:add(pf.param_bytes, buffer(12, num_elems))
        param_tree:set_len(3 + num_elems)  -- 3=12-9
        param_tree:append_text(f.param_bytes().display)
    end
    mme_tree:set_len(4 + param_tree.len)  -- 4=8+1-5
end

local function dissect_nw_info_req(buffer, mme_tree)
    mme_tree:add_le(pf.unknown, buffer(9, 1))
    mme_tree:add_le(pf.network_scope, buffer(10, 1))
    mme_tree:set_len(6)  -- 6=10+1-5
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

local function dissect_nw_stats_req(buffer, mme_tree)
    mme_tree:add_le(pf.unknown, buffer(9, 1))
    local nid_tree = mme_tree:add_le(pf.nid, buffer(10, 7))
    nid_tree.text = string.gsub(nid_tree.text, "0x00", "0x")
    nid_tree:add_le(pf.nid_sl, buffer(16, 1))
    mme_tree:set_len(12)  -- 12=10+7-5
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
        sta_tree:add_le(pf.sta_tx_rate, buffer(i + 6, 2))
        sta_tree:add_le(pf.sta_rx_spec, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_signal, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_sb, buffer(i + 8, 2))
        sta_tree:add_le(pf.sta_rx_rate, buffer(i + 8, 2))
        i = i + 10
    end
    mme_tree:set_len(5 + 10 * num_stas)  -- 5=9+1-5
end

local function dissect_set_key_req(buffer, mme_tree)
    mme_tree:add(pf.nmk, buffer(9, 16))
    mme_tree:add_le(pf.nid_kind, buffer(25, 1))
    local nid_kind = f.nid_kind()()
    if nid_kind == 0 then
        mme_tree:add_le(pf.security_level, buffer(26, 1))
        mme_tree:set_len(22)  -- 22=26+1-5
    elseif nid_kind == 1 then
        local nid_tree = mme_tree:add_le(pf.nid, buffer(26, 7))
        nid_tree.text = string.gsub(nid_tree.text, "0x00", "0x")
        nid_tree:add_le(pf.nid_sl, buffer(32, 1))
        mme_tree:add_proto_expert_info(ef.unknown_data)
    end
end

local function dissect_set_key_cnf(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_set_param_req(buffer, mme_tree)
    mme_tree:add_le(pf.param_id, buffer(9, 2))
    local param_tree = mme_tree:add(buffer(11), "Parameter: ")
    param_tree:add_le(pf.octets_per_elem, buffer(11, 1))
    param_tree:add_le(pf.num_elems, buffer(12, 2))
    local octets_per_elem = f.octets_per_elem()()
    local num_elems = f.num_elems()()
    if num_elems == 1 then
        if octets_per_elem == 4 then
            param_tree:add_le(pf.param_uint32, buffer(14, 4))
            param_tree:set_len(7)  -- 7=14+4-11
            param_tree:append_text(f.param_uint32().display)
        elseif octets_per_elem == 2 then
            param_tree:add_le(pf.param_uint16, buffer(14, 2))
            param_tree:set_len(5)  -- 5=14+2-11
            param_tree:append_text(f.param_uint16().display)
        elseif octets_per_elem == 1 then
            param_tree:add_le(pf.param_uint8, buffer(14, 1))
            param_tree:set_len(4)  -- 4=14+1-11
            param_tree:append_text(f.param_uint8().display)
        end
    elseif num_elems == 7 then
        local value_tree = param_tree:add_le(pf.param_nid, buffer(14, 7))
        param_tree:set_len(10)  -- 10=14+7-11
        value_tree.text = string.gsub(value_tree.text, "0x00", "0x")
        value_tree:add_le(pf.param_nid_sl, buffer(20, 1))
        param_tree:append_text(f.param_nid().display)
    elseif num_elems == 64 and buffer_len == 78 then  -- 78=14+64
        param_tree:add(pf.param_string, buffer(14, 64))
        param_tree:set_len(67)  -- 67=14+64-11
        param_tree:append_text(f.param_string().display)
    else
        param_tree:add(pf.param_bytes, buffer(14, num_elems))
        param_tree:set_len(3 + num_elems)  -- 3=14-11
        param_tree:append_text(f.param_bytes().display)
    end
    mme_tree:set_len(6 + param_tree.len)  -- 6=9+2-5
end

local function dissect_set_param_cnf(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_sta_info_req(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_sta_info_cnf(buffer, mme_tree)
    mme_tree:add_le(pf.chip_version, buffer(9, 4))
    mme_tree:add_le(pf.hardware_version, buffer(13, 4))
    mme_tree:add_le(pf.firmware_version_svn, buffer(17, 4))
    mme_tree:add_le(pf.chip_full_id, buffer(21, 4))
    do
        local rom_tree = mme_tree:add(buffer(21, 2), "ROM Version: ")
        rom_tree:add_le(pf.rom_version_major, buffer(21, 2))
        rom_tree:add_le(pf.rom_version_minor, buffer(21, 2))
        rom_tree:add_le(pf.rom_version_build, buffer(21, 2))
        local rom_version_major = f.rom_version_major()()
        local rom_version_minor = f.rom_version_minor()()
        local rom_version_build = f.rom_version_build()()
        rom_tree:append_text(rom_version_major .. "." .. rom_version_minor .. "." .. rom_version_build)
    end
    mme_tree:add_le(pf.param_config_bi_ver, buffer(25, 4))
    mme_tree:add_le(pf.param_config_nvm_ver, buffer(29, 4))
    mme_tree:add_le(pf.num_ucode_elems, buffer(33, 1))
    local num_ucode_elems = f.num_ucode_elems()()
    local i = 34
    if num_ucode_elems == 8 or num_ucode_elems == 10 then
        local ucodes
        if num_ucode_elems == 8 then
            ucodes = ucodes_8
        else
            ucodes = ucodes_10
        end
        for j = 1, num_ucode_elems do
            local range = buffer(i, 5)
            local ucode_tree = mme_tree:add(range, "uCode " .. j)
            ucode_tree:add(pf.ucode_name, range, ucodes[j]):set_generated(true)
            ucode_tree:add_le(pf.ucode_modified, buffer(i, 1))
            ucode_tree:add_le(pf.ucode_version, buffer(i + 1, 4))
            i = i + 5
        end
    else
        i = i + num_ucode_elems * 5
    end
    mme_tree:add_le(pf.uptime, buffer(i, 4))
    i = i + 4
    do
        local boot_msg_tree = mme_tree:add(buffer(i), "Firmware Boot Message: ")
        boot_msg_tree:add_le(pf.fw_boot_msg_len, buffer(i, 1))
        local fw_boot_msg_len = f.fw_boot_msg_len()()
        boot_msg_tree:add(pf.fw_boot_msg, buffer(i + 1, fw_boot_msg_len))
        boot_msg_tree:append_text(f.fw_boot_msg().display)
        boot_msg_tree:set_len(fw_boot_msg_len + 1)
        i = i + boot_msg_tree.len
    end
    do
        local range = buffer(i, 4)
        local fw_tree = mme_tree:add(range, "Firmware Version: ")
        fw_tree:add_le(pf.fw_version_name,  range)
        fw_tree:add_le(pf.fw_version_major, range)
        fw_tree:add_le(pf.fw_version_minor, range)
        fw_tree:add_le(pf.fw_version_build, range)
        fw_tree:append_text(to_firmware_version_string(range))
        i = i + 4
    end
    mme_tree:add_le(pf.firmware_features, buffer(i, 4))
    i = i + 4
    mme_tree:add_le(pf.flash_model, buffer(i, 4))
    i = i + 4
    mme_tree:add_le(pf.homeplug_version, buffer(i, 1))
    i = i + 1
    do
        local range = buffer(i, 1)
        mme_tree:add_le(pf.max_bit_rate, range, to_max_bit_rate_string(range))
    end
end

local function dissect_sta_restart_req(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_sta_restart_cnf(buffer, mme_tree)
    mme_tree:set_len(4)  -- 4=8+1-5
end

local function dissect_mediaxtreme_mme_v1(buffer, mme_tree)
    if mmtype == MMTYPE_DISCOVER_REQ then
        dissect_discover_req(buffer, mme_tree)
    else
        mme_tree:add_proto_expert_info(ef.unexpected_mmv_mmtype)
    end
end

local function dissect_mediaxtreme_mme_v2(buffer, mme_tree)
    if mmtype == MMTYPE_AUTHORIZE_REQ then
        dissect_authorize_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_AUTHORIZE_CNF then
        dissect_authorize_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_AUTHORIZE_IND then
        dissect_authorize_ind(buffer, mme_tree)
    elseif mmtype == MMTYPE_DISCOVER_CNF then
        dissect_discover_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_ERROR_CNF then
        dissect_error_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_ERROR_IND then
        dissect_error_ind(buffer, mme_tree)
    elseif mmtype == MMTYPE_FACTORY_RESET_REQ then
        dissect_factory_reset_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_FACTORY_RESET_CNF then
        dissect_factory_reset_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_GET_PARAM_REQ then
        dissect_get_param_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_GET_PARAM_CNF then
        dissect_get_param_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_NW_INFO_REQ then
        dissect_nw_info_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_NW_INFO_CNF then
        dissect_nw_info_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_NW_STATS_REQ then
        dissect_nw_stats_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_NW_STATS_CNF then
        dissect_nw_stats_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_SET_KEY_REQ then
        dissect_set_key_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_SET_KEY_CNF then
        dissect_set_key_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_SET_PARAM_REQ then
        dissect_set_param_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_SET_PARAM_CNF then
        dissect_set_param_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_STA_INFO_REQ then
        dissect_sta_info_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_STA_INFO_CNF then
        dissect_sta_info_cnf(buffer, mme_tree)
    elseif mmtype == MMTYPE_STA_RESTART_REQ then
        dissect_sta_restart_req(buffer, mme_tree)
    elseif mmtype == MMTYPE_STA_RESTART_CNF then
        dissect_sta_restart_cnf(buffer, mme_tree)
    else
        mme_tree:add_proto_expert_info(ef.unexpected_mmv_mmtype)
    end
end

local function update_packet_info(pinfo)
    pinfo.cols.protocol = p_mediaxtream.name
    pinfo.cols.info:set(mmtypes[mmtype])
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

    if mmtypes[mmtype] == nil then
        protocol_tree:add_proto_expert_info(ef.unknown_mmtype)
        return
    end

    update_packet_info(pinfo)

    do
        local fmi_tree = protocol_tree:add(pf.fmi, buffer(3, 2))
        fmi_tree:add(pf.fmi_nf_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fn_mi, buffer(3, 1))
        fmi_tree:add(pf.fmi_fmsn,  buffer(4, 1))
    end

    local mme_tree = protocol_tree:add(buffer(5), "Management Message Entry")

    if mmtype >= 0xa000 and mmtype < 0xc000 then
        mme_tree:add(pf.oui, buffer(5, 3)):append_text(" (" .. ouis[f.oui().label] .. ")")
        mme_tree:add_le(pf.seq_num, buffer(8, 1))
    end

    if mmv == 2 then
        dissect_mediaxtreme_mme_v2(buffer, mme_tree)
    elseif mmv == 1 then
        dissect_mediaxtreme_mme_v1(buffer, mme_tree)
    else
        mme_tree:add_proto_expert_info(ef.unexpected_mmv)
    end
end

local dt_ethertype = DissectorTable.get("ethertype")
dt_ethertype:add(ETHERTYPE_MEDIAXTREAM, p_mediaxtream)
