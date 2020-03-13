--
-- Copyright (C) 2020 Guillaume Celosia (guillaume.celosia@inria.fr) & Mathieu Cunche (mathieu.cunche@inria.fr)
--
-- This file is subject to the terms and conditions defined in file 'LICENSE', which is part of this source code package.
--

do

	------------------------------------------------------------------------------ Microsoft Connected Devices Platform (CDP) ------------------------------------------------------------------------------

	microsoft_cdp_protocol = Proto("microsoft_cdp", "Microsoft Connected Devices Platform (CDP) Protocol")

	microsoft_data = ProtoField.new("Data", "btcommon.eir_ad.entry.data", ftypes.BYTES, nil, base.NONE)
	microsoft_cdp_scenario_type = ProtoField.new("Scenario Type", "microsoft_cdp.scenario_type", ftypes.UINT8, nil, base.DEC)
	microsoft_cdp_version_nb = ProtoField.new("Version Number", "microsoft_cdp.version_number", ftypes.UINT8, nil, base.DEC, 0xc0)
	microsoft_cdp_device_type = ProtoField.uint8("microsoft_cdp.device_type", "Device Type", base.DEC, { [1] = "Xbox One", [6] = "Apple iPhone", [7] = "Apple iPad", [8] = "Android device", [9] = "Windows 10 Desktop", [11] = "Windows 10 Phone", [12] = "Linus device", [13] = "Windows IoT", [14] = "Surface Hub" }, 0x3f)
	microsoft_cdp_version = ProtoField.new("Version", "microsoft_cdp.version", ftypes.UINT8, nil, base.DEC, 0xe0)
	microsoft_cdp_flags = ProtoField.new("Flags", "microsoft_cdp.flags", ftypes.UINT8, nil, base.DEC, 0x1f)
	microsoft_cdp_reserved = ProtoField.new("Reserved", "microsoft_cdp.reserved", ftypes.UINT8, nil, base.HEX)
	microsoft_cdp_salt = ProtoField.new("Salt", "microsoft_cdp.salt", ftypes.BYTES, nil, base.NONE)
	microsoft_cdp_device_hash = ProtoField.new("Device Hash", "microsoft_cdp.device_hash", ftypes.BYTES, nil, base.NONE)
	microsoft_expert = ProtoExpert.new("btcommon.eir_ad.entry.data.undecoded", "Undecoded", expert.group.UNDECODED, expert.severity.NOTE)

	microsoft_cdp_protocol.fields = { microsoft_data, microsoft_cdp_scenario_type, microsoft_cdp_version_nb, microsoft_cdp_device_type, microsoft_cdp_version, microsoft_cdp_flags, microsoft_cdp_reserved, microsoft_cdp_salt, microsoft_cdp_device_hash }
	microsoft_cdp_protocol.experts = { microsoft_expert }

	-------- Dissect Microsoft Connected Devices Platform (CDP) --------
	function dissect_microsoft_cdp(tvb, tree)
		subtree = tree:add(microsoft_cdp_protocol, tvb(), "Microsoft Connected Devices Platform (CDP)")
		subtree:add_le(microsoft_cdp_scenario_type, tvb(0,1))
		subtree:add_le(microsoft_cdp_version_nb, tvb(1,1))
		subtree:add_le(microsoft_cdp_device_type, tvb(1,1))
		subtree:add_le(microsoft_cdp_version, tvb(2,1))
		subtree:add_le(microsoft_cdp_flags, tvb(2,1))
		subtree:add_le(microsoft_cdp_reserved, tvb(3,1))
		subtree:add_le(microsoft_cdp_salt, tvb(4,4))
		subtree:add_le(microsoft_cdp_device_hash, tvb(8,tvb:len()-8))
	end

	-------- Undecoded Microsoft Data --------
	function undecoded_microsoft_data(tvb, pinfo, tree)
		pinfo.cols.protocol = "HCI_EVT"
		subtree = tree:add_le(microsoft_data, tvb())
		subtree:add_proto_expert_info(microsoft_expert, "Undecoded")
	end

	-------- Microsoft Connected Devices Platform (CDP) Dissector -------- 
	function microsoft_cdp_protocol.dissector(tvb, pinfo, tree)
		if tvb:len() == 0 then return end
		if tvb:len() < 9 then undecoded_microsoft_data(tvb, pinfo, tree) return end

		if tvb(0,1):uint() == 0x01 then
			pinfo.cols.protocol = microsoft_cdp_protocol.name
			if not pcall(dissect_microsoft_cdp, tvb, tree) then undecoded_microsoft_data(tvb, pinfo, tree) end
		end
	end

	---------------------------------------------------------------------------------------------- Garmin BLE ----------------------------------------------------------------------------------------------

	garmin_ble_protocol = Proto("garmin_ble", "Garmin BLE Protocol")

	garmin_data = ProtoField.new("Data", "btcommon.eir_ad.entry.data", ftypes.BYTES, nil, base.NONE)
	garmin_ble_device_model = ProtoField.uint16("garmin_ble.device_model", "Device Model", base.HEX, { [0x0657] = "Forerunner 620", [0x0660] = "Forerunner 220", [0x06e5] = "Forerunner 920", [0x072c] = "Edge 1000", [0x075d] = "Vivoki", [0x0773] = "Vivoactive", [0x07a4] = "Vivosmart", [0x07c4] = "Epix", [0x0802] = "Fenix 3/Quatix 3", [0x0857] = "Vivosmart", [0x0863] = "Edge 25", [0x0864] = "Forerunner 25", [0x0869] = "Forerunner 225", [0x086c] = "Forerunner 630", [0x086d] = "Forerunner 230", [0x086e] = "Forerunner 735XT", [0x0870] = "Vivoactive", [0x08da] = "Approach S20", [0x08f4] = "Approach X40", [0x08f5] = "Fenix 3", [0x0921] = "Vivoactive HR", [0x092b] = "Vivosmart HR+", [0x092c] = "Vivosmart HR", [0x0939] = "Vivosmart HR", [0x096d] = "Fenix 3 HR", [0x097f] = "Forerunner 235", [0x09c7] = "Forerunner 35", [0x09f0] = "Fenix 5s", [0x0a2c] = "Fenix 5x/Tactix Charlie", [0x0a2e] = "Vivofit", [0x0a3e] = "Vivosmart 3", [0x0a3f] = "Vivosport", [0x0a60] = "Approach S60", [0x0a83] = "Forerunner 935", [0x0a89] = "Fenix 5", [0x0a8c] = "Vivoactive 3", [0x0ad4] = "Vivomove HR", [0x0aed] = "Fenix 5s APAC", [0x0b46] = "Forerunner 645", [0x0b4b] = "Forerunner 30" })
	garmin_expert = ProtoExpert.new("btcommon.eir_ad.entry.data.undecoded", "Undecoded", expert.group.UNDECODED, expert.severity.NOTE)

	garmin_ble_protocol.fields = { garmin_data, garmin_ble_device_model }
	garmin_ble_protocol.experts = { garmin_expert }

	-------- Dissect Garmin BLE --------
	function dissect_garmin_ble(tvb, tree)
		subtree = tree:add(garmin_ble_protocol, tvb(), "Garmin BLE")
		subtree:add_packet_field(garmin_ble_device_model, tvb(0,2), ENC_BIG_ENDIAN)
	end

	-------- Undecoded Garmin Data --------
	function undecoded_garmin_data(tvb, pinfo, tree)
		pinfo.cols.protocol = "HCI_EVT"
		subtree = tree:add_le(garmin_data, tvb())
		subtree:add_proto_expert_info(garmin_expert, "Undecoded")
	end

	-------- Garmin BLE Dissector --------
	function garmin_ble_protocol.dissector(tvb, pinfo, tree)
		if tvb:len() == 0 then return end
		if tvb:len() < 2 or tvb:len() > 2 then undecoded_garmin_data(tvb, pinfo, tree) return 
		else
			pinfo.cols.protocol = garmin_ble_protocol.name
			if not pcall(dissect_garmin_ble, tvb, tree) then undecoded_garmin_data(tvb, pinfo, tree) end
		end
	end

	------------------------------------------------------------------------------------------- Apple Continuity -------------------------------------------------------------------------------------------

	apple_continuity_protocol = Proto("apple_continuity", "Apple Continuity Protocol")
	apple_reserved = Proto("apple_reserved", "Apple Reserved")
	apple_hash = Proto("apple_hash", "Apple Hash")
	apple_ibeacon = Proto("apple_ibeacon", "Apple iBeacon ")
	apple_airprint = Proto("apple_airprint", "Apple AirPrint")
	appletv_setup = Proto("appletv_setup", "AppleTV Setup")
	apple_airdrop = Proto("apple_airdrop", "Apple AirDrop")
	apple_airdrop_hashes = Proto("apple_airdrop.hashes", "Hashes")
	apple_homekit = Proto("apple_homekit", "Apple HomeKit")
	apple_proximity_pairing = Proto("apple_proximity_pairing", "Apple Proximity Pairing")
	apple_proximity_pairing_battery_indication_1 = Proto("apple_proximity_pairing.battery_indication_1", "Battery Indication 1")
	apple_proximity_pairing_battery_indication_2 = Proto("apple_proximity_pairing.battery_indication_2", "Battery Indication 2")
	apple_hey_siri = Proto("apple_hey_siri", "Apple \"Hey Siri\"")
	apple_airplay_target = Proto("apple_airplay_target", "Apple AirPlay Target")
	apple_airplay_solo_source = Proto("apple_airplay_solo_source", "Apple Airplay Solo Source")
	apple_magic_switch = Proto("apple_magic_switch", "Apple Magic Switch")
	apple_handoff = Proto("apple_handoff", "Apple Handoff")
	apple_tethering_target_presence = Proto("apple_tethering_target_presence", "Apple Tethering Target Presence")
	apple_tethering_source_presence = Proto("apple_tethering_source_presence", "Apple Tethering Source Presence")
	apple_tethering_source_presence_flags = Proto("apple_tethering_source_presence.flags", "Flags")
	apple_nearby_action = Proto("apple_nearby_action", "Apple Nearby Action")
	apple_nearby_action_flags = Proto("apple_nearby_action.flags", "Flags ")
	apple_nearby_action_parameters = Proto("apple_nearby_action.parameters", "Parameters")
	apple_nearby_action_parameters_repair_problem_flags = Proto("apple_nearby_action.parameters.repair.problem_flags", "Problem Flags")
	apple_nearby_info = Proto("apple_nearby_info", "Apple Nearby Info")
	apple_nearby_info_information = Proto("apple_nearby_info.information", "Information")
	apple_homekit_encrypted_notification = Proto("apple_homekit_encrypted_notification", "Apple HomeKit Encrypted Notification")
	apple_continuity_undecoded_message = Proto("apple_continuity_undecoded_message", "Apple Continuity Undecoded Message")

	btcommon_eir_ad_entry_data = ProtoField.new("Data", "btcommon.eir_ad.entry.data", ftypes.BYTES, nil, base.NONE)

	apple_reserved_data = ProtoField.new("Data", "apple_reserved.data", ftypes.BYTES, nil, base.NONE)

	apple_hash_hash = ProtoField.new("Hash", "apple_hash.hash", ftypes.BYTES, nil, base.NONE)

	apple_ibeacon_proximity_uuid = ProtoField.new("Proximity UUID", "apple_ibeacon.proximity_uuid", ftypes.BYTES, nil, base.NONE)
	apple_ibeacon_major = ProtoField.new("Major", "apple_ibeacon.major", ftypes.UINT16, nil, base.DEC)
	apple_ibeacon_minor = ProtoField.new("Minor", "apple_ibeacon.minor", ftypes.UINT16, nil, base.DEC)
	apple_ibeacon_signal_power = ProtoField.new("Signal Power (dB)", "apple_ibeacon.signal_power", ftypes.INT8, nil, base.DEC)

	apple_airprint_address_type = ProtoField.uint8("apple_airprint.address_type", "Address Type", base.HEX, { [0x11] = "IPv4" } )
	apple_airprint_resource_path_type = ProtoField.new("Resource Path Type", "apple_airprint.resource_path_type", ftypes.UINT8, nil, base.DEC)
	apple_airprint_security_type = ProtoField.new("Security type", "apple_airprint.security_type", ftypes.UINT8, nil, base.DEC)
	apple_airprint_qic_tcp_port = ProtoField.new("QID or TCP Port", "apple_airprint.qid_tcp_port", ftypes.UINT16, nil, base.DEC)
	apple_airprint_ipv4_address = ProtoField.new("IPv4 Address", "apple_airprint.ipv4_address", ftypes.IPv4)
	apple_airprint_ipv6_address = ProtoField.new("IPv6 Address", "apple_airprint.ipv6_address", ftypes.IPv6)
	apple_airprint_measured_power = ProtoField.new("Measured Power", "apple_airprint.measured_power", ftypes.INT8, nil, base.DEC)

	appletv_setup_data = ProtoField.new("Data", "appletv_setup.data", ftypes.BYTES, nil, base.NONE)

	apple_airdrop_version = ProtoField.new("Version", "apple_airdrop.version", ftypes.UINT8, nil, base.DEC)
	apple_airdrop_hash_0 = ProtoField.new("SHA-256 Hash 0 (E-mail/Apple ID/Phone)", "apple_airdrop.hashes.hash_0", ftypes.BYTES, nil, base.NONE)
	apple_airdrop_hash_1 = ProtoField.new("SHA-256 Hash 1 (E-mail/Apple ID/Phone)", "apple_airdrop.hashes.hash_1", ftypes.BYTES, nil, base.NONE)
	apple_airdrop_hash_2 = ProtoField.new("SHA-256 Hash 2 (E-mail/Apple ID/Phone)", "apple_airdrop.hashes.hash_2", ftypes.BYTES, nil, base.NONE)
	apple_airdrop_hash_3 = ProtoField.new("SHA-256 Hash 3 (E-mail/Apple ID/Phone)", "apple_airdrop.hashes.hash_3", ftypes.BYTES, nil, base.NONE)

	apple_homekit_subtype = ProtoField.uint8("apple_homekit.subtype", "SubType", base.HEX, { [0x1] = "HomeKit regular advertisement" }, 0xe0)
	apple_homekit_length = ProtoField.new("Length", "apple_homekit.length", ftypes.UINT8, nil, base.DEC, 0x1f)
	apple_homekit_reserved = ProtoField.new("Reserved", "apple_homekit.reserved", ftypes.UINT8, nil, base.DEC, 0xfe)
	apple_homekit_hap_pairing_status_flag = ProtoField.uint8("apple_homekit.hap_pairing_status_flag", "HAP Pairing Status Flag", base.HEX, { [0x0] = "The accessory has been paired with a controllers", [0x1] = "The accessory has not been paired with any controllers" }, 0x01)
	apple_homekit_device_id = ProtoField.new("Device ID", "apple_homekit.device_id", ftypes.BYTES, nil, base.NONE)
	apple_homekit_accessory_category_identifier = ProtoField.uint16( "apple_homekit.accessory_category_identifier", "Accessory Category Identifier", base.DEC, { [1] = "Other", [2] = "Bridges", [3] = "Fans", [4] = "Garage Door Openers", [5] = "Lighting", [6] = "Locks", [7] = "Outlets", [8] = "Switches", [9] = "Thermostats", [10] = "Sensors", [11] = "Security Systems", [12] = "Doors", [13] = "Windows", [14] = "Window Coverings", [15] = "Programmable Switches", [16] = "Reserved", [17] = "IP Cameras", [18] = "Video Doorbells", [19] = "Air Purifiers", [20] = "Heaters", [21] = "Air Conditioners", [22] = "Humidifiers", [23] = "Dehumidifiers", [24] = "Reserved", [25] = "Reserved", [26] = "Reserved", [27] = "Reserved", [28] = "Sprinklers", [29] = "Faucets", [30] = "Shower Systems", [31] = "Reserved", [32] = "Remotes" })
	apple_homekit_global_state_number = ProtoField.new("Global State Number", "apple_homekit.global_state_number", ftypes.UINT16, nil, base.HEX)
	apple_homekit_configuration_number = ProtoField.new("Configuration Number", "apple_homekit.configuration_number", ftypes.UINT8, nil, base.DEC)
	apple_homekit_compatible_version = ProtoField.new("Compatible Version", "apple_homekit.compatible_version", ftypes.UINT8, nil, base.DEC)
	apple_homekit_setup_hash = ProtoField.new("Setup Hash", "apple_homekit.setup_hash", ftypes.UINT32, nil, base.HEX)

	apple_proximity_pairing_status = ProtoField.uint8("apple_proximity_pairing.status", "Status", base.HEX, { [0x00] = "Unpaired", [0x01] = "Paired" })
	apple_proximity_pairing_device_model = ProtoField.uint16("apple_proximity_pairing.device_model", "Device Model", base.HEX, { [0x0220] = "AirPods", [0x0320] = "Powerbeats3", [0x0520] = "BeatsX", [0x0620] = "Beats Solo3" })
	apple_proximity_pairing_public_address = ProtoField.new("Public Address", "apple_proximity_pairing.public_address", ftypes.BYTES, nil, base.NONE)
	apple_proximity_pairing_utp = ProtoField.uint8("apple_proximity_pairing.utp", "UTP", base.HEX, { [0x01] = "In Ear", [0x02] = "In Case", [0x03] = "Airplane" })
	apple_proximity_pairing_unpaired_charging_battery_level_1 = ProtoField.new("Battery Level 1 (%) (charging)", "apple_proximity_pairing.battery_level_1", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_charging_battery_level_2 = ProtoField.new("Battery Level 2 (%) (charging)", "apple_proximity_pairing.battery_level_2", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_charging_battery_level_3 = ProtoField.new("Battery Level 3 (%) (charging)", "apple_proximity_pairing.battery_level_3", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_discharging_battery_level_1 = ProtoField.new("Battery Level 1 (%) (discharging)", "apple_proximity_pairing.battery_level_1", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_discharging_battery_level_2 = ProtoField.new("Battery Level 2 (%) (discharging)", "apple_proximity_pairing.battery_level_2", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_discharging_battery_level_3 = ProtoField.new("Battery Level 3 (%) (discharging)", "apple_proximity_pairing.battery_level_3", ftypes.INT8, nil, base.DEC)
	apple_proximity_pairing_unpaired_no_battery_level_1 = ProtoField.new("No Battery Level 1", "apple_proximity_pairing.no_battery_level_1", ftypes.UINT8, nil, base.HEX)
	apple_proximity_pairing_unpaired_no_battery_level_2 = ProtoField.new("No Battery Level 2", "apple_proximity_pairing.no_battery_level_2", ftypes.UINT8, nil, base.HEX)
	apple_proximity_pairing_unpaired_no_battery_level_3 = ProtoField.new("No Battery Level 3", "apple_proximity_pairing.no_battery_level_3", ftypes.UINT8, nil, base.HEX)
	apple_proximity_pairing_paired_battery_level_1 = ProtoField.new("Battery Level 1 (x10%)", "apple_proximity_pairing.battery_indication_1.battery_level_1", ftypes.UINT8, nil, base.DEC, 0xf0)
	apple_proximity_pairing_paired_battery_level_2 = ProtoField.new("Battery Level 2 (x10%)", "apple_proximity_pairing.battery_indication_1.battery_level_2", ftypes.UINT8, nil, base.DEC, 0x0f)
	apple_proximity_pairing_paired_battery_level_3 = ProtoField.new("Battery Level 3 (x10%)", "apple_proximity_pairing.battery_indication_2.battery_level_3", ftypes.UINT8, nil, base.DEC, 0x0f)
	apple_proximity_pairing_paired_no_battery_level_1 = ProtoField.new("No Battery Level 1", "apple_proximity_pairing.battery_indication_1.no_battery_level_1", ftypes.UINT8, nil, base.HEX, 0xf0)
	apple_proximity_pairing_paired_no_battery_level_2 = ProtoField.new("No Battery Level 2", "apple_proximity_pairing.battery_indication_1.no_battery_level_2", ftypes.UINT8, nil, base.HEX, 0x0f)
	apple_proximity_pairing_paired_no_battery_level_3 = ProtoField.new("No Battery Level 3", "apple_proximity_pairing.battery_indication_2.no_battery_level_3", ftypes.UINT8, nil, base.HEX, 0x0f)
	apple_proximity_pairing_lid_open_count = ProtoField.new("Lid Open Count", "apple_proximity_pairing.lid_open_count", ftypes.UINT8, nil, base.DEC)
	apple_proximity_pairing_case_charging = ProtoField.new("Case Charging", "apple_proximity_pairing.battery_indication_2.case_charging", ftypes.BOOLEAN, nil, 8, 0x40)
	apple_proximity_pairing_right_charging = ProtoField.new("Right Charging", "apple_proximity_pairing.battery_indication_2.right_charging", ftypes.BOOLEAN, nil, 8, 0x20)
	apple_proximity_pairing_left_charging = ProtoField.new("Left Charging", "apple_proximity_pairing.battery_indication_2.left_charging", ftypes.BOOLEAN, nil, 8, 0x10)
	apple_proximity_pairing_device_color = ProtoField.uint8("apple_proximity_pairing.device_color", "Device Color", base.HEX, { [0x00] = "White", [0x01] = "Black", [0x02] = "Red", [0x03] = "Blue", [0x04] = "Pink", [0x05] = "Gray", [0x06] = "Silver", [0x07] = "Gold", [0x08] = "Rose Gold", [0x09] = "Space Gray", [0x0a] = "Dark Blue", [0x0b] = "Light Blue", [0x0c] = "Yellow" })
	apple_proximity_pairing_encrypted_payload = ProtoField.new("AES-128-ECB Encrypted Payload", "apple_proximity_pairing.encrypted_payload", ftypes.BYTES, nil, base.NONE)

	apple_hey_siri_perceptual_hash = ProtoField.new("Perceptual Hash", "apple_hey_siri.perceptual_hash", ftypes.BYTES, nil, base.NONE)
	apple_hey_siri_snr = ProtoField.new("Signal-to-noise Ratio (SNR)", "apple_hey_siri.snr", ftypes.UINT8, nil, base.DEC)
	apple_hey_siri_confidence = ProtoField.new("Confidence", "apple_hey_siri.confidence", ftypes.UINT8, nil, base.DEC)
	apple_hey_siri_device_class = ProtoField.uint16("apple_hey_siri.device_class", "Device Class", base.HEX, { [0x0002] = "iPhone", [0x0003] = "iPad", [0x0009] = "MacBook", [0x000a] = "Watch" })
	apple_hey_siri_random_byte = ProtoField.new("Random Byte", "apple_hey_siri.random_byte", ftypes.UINT8, nil, base.HEX)

	apple_airplay_target_flags = ProtoField.new("Flags", "apple_airplay_target.flags", ftypes.UINT8, nil, base.HEX)
	apple_airplay_target_config_seed = ProtoField.new("Config Seed", "apple_airplay_target.config_seed", ftypes.UINT8, nil, base.HEX)
	apple_airplay_target_ipv4_address = ProtoField.new("IPv4 Address", "apple_airplay_target.ipv4_address", ftypes.IPv4)

	apple_airplay_solo_source_data = ProtoField.new("Data", "apple_airplay_solo_source.data", ftypes.BYTES, nil, base.NONE)

	apple_magic_switch_data = ProtoField.new("Data", "apple_magic_switch.data", ftypes.BYTES, nil, base.NONE)
	apple_magic_switch_confidence_on_wrist = ProtoField.uint8("apple_magic_switch.confidence_on_wrist", "Confidence On Wrist", base.HEX, { [0x03] = "Not on wrist", [0x1f] = "Wrist detection disabled", [0x3f] = "On wrist" })

	apple_handoff_version = ProtoField.new("Version", "apple_handoff.version", ftypes.UINT8, nil, base.DEC)
	apple_handoff_iv = ProtoField.new("Initialization Vector (IV)", "apple_handoff.iv", ftypes.UINT16, nil, base.HEX)
	apple_handoff_auth_tag = ProtoField.new("AES-GCM Auth Tag", "apple_handoff.auth_tag", ftypes.UINT8, nil, base.HEX)
	apple_handoff_encrypted_payload = ProtoField.new("AES-256-ECB Encrypted Payload", "apple_handoff.encrypted_payload", ftypes.BYTES, nil, base.NONE)

	apple_tethering_target_presence_identifier = ProtoField.new("Identifier", "apple_tethering_target_presence.identifier", ftypes.BYTES, nil, base.NONE)

	apple_tethering_source_presence_version = ProtoField.new("Version", "apple_tethering_source_presence.version", ftypes.UINT8, nil, base.DEC)
	apple_tethering_source_presence_duplicate_uuids = ProtoField.new("Duplicate UUIDs", "apple_tethering_source_presence.flags.duplicate_uuids", ftypes.BOOLEAN, nil, 8, 0x80)
	apple_tethering_source_presence_battery_level = ProtoField.new("Battery Level (%)", "apple_tethering_source_presence.battery_level", ftypes.UINT16, nil, base.DEC)
	apple_tethering_source_presence_network_type = ProtoField.uint8("apple_tethering_source_presence.network_type", "Network Type", base.HEX, { [0x01] = "1xRTT", [0x02] = "GPRS", [0x03] = "EDGE", [0x04] = "3G (EV-DO)", [0x05] = "3G", [0x06] = "4G", [0x07] = "LTE" })
	apple_tethering_source_presence_signal_strength = ProtoField.new("Signal Strength (cell bars)", "apple_tethering_source_presence.signal_strength", ftypes.UINT8, nil, base.DEC)

	apple_nearby_action_has_auth_tag = ProtoField.new("Has Auth Tag", "apple_nearby_action.flags.has_auth_tag", ftypes.BOOLEAN, nil, 8, 0x80)
	apple_nearby_action_needs_setup = ProtoField.new("Needs Setup", "apple_nearby_action.flags.needs_setup", ftypes.BOOLEAN, nil, 8, 0x40)
	apple_nearby_action_needs_keyboard = ProtoField.new("Needs Keyboard", "apple_nearby_action.flags.needs_keyboard", ftypes.BOOLEAN, nil, 8, 0x20)
	apple_nearby_action_needs_awdl = ProtoField.new("Needs AWDL", "apple_nearby_action.flags.needs_awdl", ftypes.BOOLEAN, nil, 8, 0x10)
	apple_nearby_action_needs_nan = ProtoField.new("Needs NAN", "apple_nearby_action.flags.needs_nan", ftypes.BOOLEAN, nil, 8, 0x08)
	apple_nearby_action_type = ProtoField.uint8("apple_nearby_action.type", "Type", base.HEX, { [0x01] = "AppleTV Tap-To-Setup", [0x04] = "Mobile Backup", [0x05] = "Watch Setup", [0x06] = "AppleTV Pair", [0x07] = "Internet Relay", [0x08] = "Wi-Fi Password", [0x09] = "iOS Setup", [0x0a] = "Repair", [0x0b] = "Speaker Setup", [0x0c] = "ApplePay", [0x0d] = "Whole Home Audio Setup", [0x0e] = "Developer Tools Pairing Request", [0x0f] = "Answered Call", [0x10] = "Ended Call", [0x11] = "DD Ping", [0x12] = "DD Pong", [0x13] = "Remote Auto Fill", [0x14] = "Companion Link Prox", [0x15] = "Remote Management", [0x16] = "Remote Auto Fill Pong", [0x17] = "Remote Display" })
	apple_nearby_action_auth_tag = ProtoField.new("Auth Tag", "apple_nearby_action.auth_tag", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_parameters_data = ProtoField.new("Data", "apple_nearby_action.parameters.data", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_wifi_password_hash_0 = ProtoField.new("SHA-256 Hash 0 (E-mail/Apple ID/Phone)", "apple_nearby_action.parameters.wifi_password.hash_0", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_wifi_password_hash_1 = ProtoField.new("SHA-256 Hash 1 (E-mail/Apple ID/Phone)", "apple_nearby_action.parameters.wifi_password.hash_1", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_wifi_password_hash_2 = ProtoField.new("SHA-256 Hash 2 (E-mail/Apple ID/Phone)", "apple_nearby_action.parameters.wifi_password.hash_2", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_wifi_password_hash_3 = ProtoField.new("SHA-256 Hash 3 (SSID)", "apple_nearby_action.parameters.wifi_password.hash_3", ftypes.BYTES, nil, base.NONE)
	apple_nearby_action_ios_setup_device_class = ProtoField.uint8("apple_nearby_action.parameters.ios_setup.device_class", "Device Class", base.HEX, { [0x2] = "iPhone", [0x4] = "iPod", [0x6] = "iPad", [0x8] = "Audio accessory (HomePod)", [0xa] = "Mac", [0xc] = "AppleTV", [0xe] = "Watch" }, 0xf0)
	apple_nearby_action_ios_setup_device_model = ProtoField.uint8("apple_nearby_action.parameters.ios_setup.device_model", "Device Model", base.HEX, { [0x1] = "D22ish", [0x2] = "SEish", [0x3] = "JEXXish" }, 0x0f)
	apple_nearby_action_ios_setup_device_color = ProtoField.uint8("apple_nearby_action.parameters.ios_setup.device_color", "Device Color", base.HEX, { [0x00] = "Unknown", [0x01] = "Black", [0x02] = "White", [0x03] = "Red", [0x04] = "Silver", [0x05] = "Pink", [0x06] = "Blue", [0x07] = "Yellow", [0x08] = "Gold", [0x09] = "Sparrow" })
	apple_nearby_action_ios_setup_os_version = ProtoField.new("OS Version", "apple_nearby_action.parameters.ios_setup.os_version", ftypes.UINT8, nil, base.DEC)
	apple_nearby_action_wifiperf = ProtoField.new("WiFiPerf", "apple_nearby_action.parameters.repair.problem_flags.wifiperf", ftypes.BOOLEAN, nil, 8, 0x10)
	apple_nearby_action_wifi = ProtoField.new("WiFi", "apple_nearby_action.parameters.repair.problem_flags.wifi", ftypes.BOOLEAN, nil, 8, 0x08)
	apple_nearby_action_homekit = ProtoField.new("HomeKit", "apple_nearby_action.parameters.repair.problem_flags.homekit", ftypes.BOOLEAN, nil, 8, 0x04)
	apple_nearby_action_itunes = ProtoField.new("iTunes", "apple_nearby_action.parameters.repair.problem_flags.itunes", ftypes.BOOLEAN, nil, 8, 0x02)
	apple_nearby_action_icloud = ProtoField.new("iCloud", "apple_nearby_action.parameters.repair.problem_flags.icloud", ftypes.BOOLEAN, nil, 8, 0x01)

	apple_nearby_info_activity_level = ProtoField.uint8("apple_nearby_info.activity_level", "Activity Level", base.HEX, { [0x0] = "Activity level is not known", [0x1] = "Activity reporting is disabled", [0x3] = "User is idle", [0x5] = "Audio is playing with the screen off", [0x7] = "Screen is on", [0x9] = "Screen on and video playing", [0xa] = "Watch is on wrist and unlocked", [0xb] = "Recent user interaction", [0xd] = "User is driving a vehicle", [0xe] = "Phone call or Facetime" }, 0x0f)
	apple_nearby_info_auto_unlock_enabled = ProtoField.new("Auto Unlock Enabled", "apple_nearby_info.information.auto_unlock_enabled", ftypes.BOOLEAN, nil, 8, 0x80)
	apple_nearby_info_auto_unlock_watch = ProtoField.new("Auto Unlock Watch", "apple_nearby_info.information.auto_unlock_watch", ftypes.BOOLEAN, nil, 8, 0x40)
	apple_nearby_info_watch_locked = ProtoField.new("Watch Locked", "apple_nearby_info.information.watch_locked", ftypes.BOOLEAN, nil, 8, 0x20)
	apple_nearby_info_has_auth_tag = ProtoField.new("Has Auth Tag", "apple_nearby_info.information.has_auth_tag", ftypes.BOOLEAN, nil, 8, 0x10)
	apple_nearby_info_auth_tag = ProtoField.new("Auth Tag", "apple_nearby_info.auth_tag", ftypes.BYTES, nil, base.NONE)

	apple_homekit_encrypted_notification_subtype = ProtoField.uint8("apple_homekit_encrypted_notification.subtype", "SubType", base.HEX, { [0x1] = "HomeKit encrypted notification" }, 0xe0)
	apple_homekit_encrypted_notification_length = ProtoField.new("Length", "apple_homekit_encrypted_notification.length", ftypes.UINT8, nil, base.DEC, 0x1f)
	apple_homekit_encrypted_notification_accessory_advertising_identifier = ProtoField.new("Accessory Advertising Identifier", "apple_homekit_encrypted_notification.accessory_advertising_identifier", ftypes.BYTES, nil, base.NONE)
	apple_homekit_encrypted_notification_global_state_number = ProtoField.new("Global State Number", "apple_homekit_encrypted_notification.global_state_number", ftypes.UINT16, nil, base.HEX)
	apple_homekit_encrypted_notification_characteristic_instance_id = ProtoField.new("Characteristic Instance ID", "apple_homekit_encrypted_notification.characteristic_instance_id", ftypes.BYTES, nil, base.NONE)
	apple_homekit_encrypted_notification_value = ProtoField.new("Value", "apple_homekit_encrypted_notification.value", ftypes.UINT64, nil, base.HEX)
	apple_homekit_encrypted_notification_auth_tag = ProtoField.new("Auth Tag", "apple_homekit_encrypted_notification.auth_tag", ftypes.BYTES, nil, base.NONE)

	apple_continuity_undecoded_message_type = ProtoField.uint8("apple_continuity_undecoded_message.type", "Type", base.HEX, {})
	apple_continuity_undecoded_message_length = ProtoField.new("Length", "apple_continuity_undecoded_message.length", ftypes.UINT8, nil, base.DEC)
	apple_continuity_undecoded_message_data = ProtoField.new("Data", "apple_continuity_undecoded_message.data", ftypes.BYTES, nil, base.NONE)

	btcommon_eir_ad_entry_data_undecoded = ProtoExpert.new("btcommon.eir_ad.entry.data.undecoded", "Undecoded", expert.group.UNDECODED, expert.severity.NOTE)

	apple_continuity_protocol.fields = { btcommon_eir_ad_entry_data }
	apple_reserved.fields = { apple_reserved_data }
	apple_hash.fields = { apple_hash_hash }
	apple_ibeacon.fields = { apple_ibeacon_proximity_uuid, apple_ibeacon_major, apple_ibeacon_minor, apple_ibeacon_signal_power }
	apple_airprint.fields = { apple_airprint_address_type, apple_airprint_resource_path_type, apple_airprint_security_type, apple_airprint_qic_tcp_port, apple_airprint_ipv4_address, apple_airprint_ipv6_address, apple_airprint_measured_power }
	appletv_setup.fields = { appletv_setup_data }
	apple_airdrop.fields = { apple_airdrop_version }
	apple_airdrop_hashes.fields = { apple_airdrop_hash_0, apple_airdrop_hash_1, apple_airdrop_hash_2, apple_airdrop_hash_3 }
	apple_homekit.fields = { apple_homekit_subtype, apple_homekit_length, apple_homekit_reserved, apple_homekit_hap_pairing_status_flag, apple_homekit_device_id, apple_homekit_accessory_category_identifier, apple_homekit_global_state_number, apple_homekit_configuration_number, apple_homekit_compatible_version, apple_homekit_setup_hash }
	apple_proximity_pairing.fields = { apple_proximity_pairing_status, apple_proximity_pairing_device_model, apple_proximity_pairing_public_address, apple_proximity_pairing_utp, apple_proximity_pairing_unpaired_charging_battery_level_1, apple_proximity_pairing_unpaired_charging_battery_level_2, apple_proximity_pairing_unpaired_charging_battery_level_3, apple_proximity_pairing_unpaired_discharging_battery_level_1, apple_proximity_pairing_unpaired_discharging_battery_level_2, apple_proximity_pairing_unpaired_discharging_battery_level_3, apple_proximity_pairing_unpaired_no_battery_level_1, apple_proximity_pairing_unpaired_no_battery_level_2, apple_proximity_pairing_unpaired_no_battery_level_3, apple_proximity_pairing_lid_open_count, apple_proximity_pairing_device_color, apple_proximity_pairing_encrypted_payload }
	apple_proximity_pairing_battery_indication_1.fields = { apple_proximity_pairing_paired_battery_level_1, apple_proximity_pairing_paired_battery_level_2, apple_proximity_pairing_paired_no_battery_level_1, apple_proximity_pairing_paired_no_battery_level_2 }
	apple_proximity_pairing_battery_indication_2.fields = { apple_proximity_pairing_case_charging, apple_proximity_pairing_right_charging, apple_proximity_pairing_left_charging, apple_proximity_pairing_paired_battery_level_3, apple_proximity_pairing_paired_no_battery_level_3 }
	apple_hey_siri.fields = { apple_hey_siri_perceptual_hash, apple_hey_siri_snr, apple_hey_siri_confidence, apple_hey_siri_device_class, apple_hey_siri_random_byte }
	apple_airplay_target.fields = { apple_airplay_target_flags, apple_airplay_target_config_seed, apple_airplay_target_ipv4_address }
	apple_airplay_solo_source.fields = { apple_airplay_solo_source_data }
	apple_magic_switch.fields = { apple_magic_switch_data, apple_magic_switch_confidence_on_wrist }
	apple_handoff.fields = { apple_handoff_version, apple_handoff_iv, apple_handoff_auth_tag, apple_handoff_encrypted_payload }
	apple_tethering_target_presence.fields = { apple_tethering_target_presence_identifier }
	apple_tethering_source_presence.fields = { apple_tethering_source_presence_version, apple_tethering_source_presence_battery_level, apple_tethering_source_presence_network_type, apple_tethering_source_presence_signal_strength }
	apple_tethering_source_presence_flags.fields = { apple_tethering_source_presence_duplicate_uuids }
	apple_nearby_action.fields = { apple_nearby_action_type, apple_nearby_action_auth_tag}
	apple_nearby_action_flags.fields = {apple_nearby_action_has_auth_tag, apple_nearby_action_needs_setup, apple_nearby_action_needs_keyboard, apple_nearby_action_needs_awdl, apple_nearby_action_needs_nan}
	apple_nearby_action_parameters.fields = { apple_nearby_action_parameters_data, apple_nearby_action_wifi_password_hash_0, apple_nearby_action_wifi_password_hash_1, apple_nearby_action_wifi_password_hash_2, apple_nearby_action_wifi_password_hash_3, apple_nearby_action_ios_setup_device_class, apple_nearby_action_ios_setup_device_model, apple_nearby_action_ios_setup_device_color, apple_nearby_action_ios_setup_os_version }
	apple_nearby_action_parameters_repair_problem_flags.fields = { apple_nearby_action_wifiperf, apple_nearby_action_wifi, apple_nearby_action_homekit, apple_nearby_action_itunes, apple_nearby_action_icloud }
	apple_nearby_info.fields = { apple_nearby_info_activity_level, apple_nearby_info_auth_tag }
	apple_nearby_info_information.fields = { apple_nearby_info_auto_unlock_enabled, apple_nearby_info_auto_unlock_watch, apple_nearby_info_watch_locked, apple_nearby_info_has_auth_tag }
	apple_homekit_encrypted_notification.fields = { apple_homekit_encrypted_notification_subtype, apple_homekit_encrypted_notification_length, apple_homekit_encrypted_notification_accessory_advertising_identifier, apple_homekit_encrypted_notification_global_state_number, apple_homekit_encrypted_notification_characteristic_instance_id, apple_homekit_encrypted_notification_value, apple_homekit_encrypted_notification_auth_tag }
	apple_continuity_undecoded_message.fields = { apple_continuity_undecoded_message_type, apple_continuity_undecoded_message_length, apple_continuity_undecoded_message_data }
	apple_continuity_protocol.experts = { btcommon_eir_ad_entry_data_undecoded }

	-------- Dissect Apple Reserved --------
	function dissect_apple_reserved(offset, lgth, tvb, tree)
		subtree = tree:add(apple_reserved, tvb(offset,lgth+2), "Apple Reserved")
		subtree:add_le(apple_reserved_data, tvb(offset+2,lgth))
	end

	-------- Dissect Apple Hash --------
	function dissect_apple_hash(offset, lgth, tvb, tree)
		subtree = tree:add(apple_hash, tvb(offset,lgth+2), "Apple Hash")
		subtree:add_le(apple_hash_hash, tvb(offset+2,lgth))
	end

	-------- Dissect Apple iBeacon --------
	function dissect_apple_ibeacon(offset, lgth, tvb, tree)
		subtree = tree:add(apple_ibeacon, tvb(offset,lgth+2), "Apple iBeacon")
		subtree:add_le(apple_ibeacon_proximity_uuid, tvb(offset+2,16))
		subtree:add_packet_field(apple_ibeacon_major, tvb(offset+18,2), ENC_BIG_ENDIAN)
		subtree:add_packet_field(apple_ibeacon_minor, tvb(offset+20,2), ENC_BIG_ENDIAN)
		subtree:add_le(apple_ibeacon_signal_power, tvb(offset+22,1))
	end

	-------- Dissect Apple AirPrint --------
	function dissect_apple_airprint(offset, lgth, tvb, tree)
		subtree = tree:add(apple_airprint, tvb(offset,lgth+2), "Apple AirPrint")
		subtree:add_le(apple_airprint_address_type, tvb(offset+2,1))
		subtree:add_le(apple_airprint_resource_path_type, tvb(offset+3,1))
		subtree:add_le(apple_airprint_security_type, tvb(offset+4,1))
		subtree:add_packet_field(apple_airprint_qic_tcp_port, tvb(offset+5,2), ENC_BIG_ENDIAN)
		if tvb(offset+2,1):uint() == 0x11 then
			subtree:add_packet_field(apple_airprint_ipv4_address, tvb(offset+7,4), ENC_BIG_ENDIAN)
		--else
			--subtree:add_le(apple_airprint_ipv6_address, tvb(offset+7,16))
		end
		subtree:add_le(apple_airprint_measured_power, tvb(offset+23,1))
	end

	-------- Dissect AppleTV Setup --------
	function dissect_appletv_setup(offset, lgth, tvb, tree)
		subtree = tree:add(appletv_setup, tvb(offset,lgth+2), "AppleTV Setup")
		subtree:add_le(appletv_setup_data, tvb(offset+2,lgth))
	end

	-------- Dissect Apple AirDrop --------
	function dissect_apple_airdrop(offset, lgth, tvb, tree)
		subtree = tree:add(apple_airdrop, tvb(offset,lgth+2), "Apple AirDrop")
		subtree:add_le(apple_airdrop_version, tvb(offset+10,1))
		aidrop_hashes = subtree:add(apple_airdrop_hashes, tvb(offset+11,8), "Hashes")
		aidrop_hashes:add_le(apple_airdrop_hash_0, tvb(offset+11,2))
		aidrop_hashes:add_le(apple_airdrop_hash_1, tvb(offset+13,2))
		aidrop_hashes:add_le(apple_airdrop_hash_2, tvb(offset+15,2))
		aidrop_hashes:add_le(apple_airdrop_hash_3, tvb(offset+17,2))
	end

	-------- Dissect Apple HomeKit --------
	function dissect_apple_homekit(offset, lgth, tvb, tree)
		subtree = tree:add(apple_homekit, tvb(offset,tvb(offset+1,1):bitfield(3,5)+2), "Apple HomeKit")
		subtree:add_le(apple_homekit_subtype, tvb(offset+1,1))
		subtree:add_le(apple_homekit_length, tvb(offset+1,1))
		subtree:add_le(apple_homekit_reserved, tvb(offset+2,1))
		subtree:add_le(apple_homekit_hap_pairing_status_flag, tvb(offset+2,1))
		subtree:add_le(apple_homekit_device_id, tvb(offset+3,6))
		subtree:add_le(apple_homekit_accessory_category_identifier, tvb(offset+9,2))
		subtree:add_le(apple_homekit_global_state_number, tvb(offset+11,2))
		subtree:add_le(apple_homekit_configuration_number, tvb(offset+13,1))
		subtree:add_le(apple_homekit_compatible_version, tvb(offset+14,1))
		if tvb(offset+1,1):bitfield(3,5) == 17 then
			subtree:add_le(apple_homekit_setup_hash, tvb(offset+15,4))
		end
	end

	-------- Dissect Apple Proximity Pairing --------
	function dissect_apple_proximity_pairing(offset, lgth, tvb, tree)
		subtree = tree:add(apple_proximity_pairing, tvb(offset,lgth+2), "Apple Proximity Pairing")
		subtree:add_le(apple_proximity_pairing_status, tvb(offset+2,1))
		subtree:add_packet_field(apple_proximity_pairing_device_model, tvb(offset+3,2), ENC_BIG_ENDIAN)

		---- Unpaired ----
		if tvb(offset+2,1):uint() == 0x00 then
			subtree:add_le(apple_proximity_pairing_public_address, tvb(offset+5,6))
			subtree:add_le(apple_proximity_pairing_utp, tvb(offset+11,1))
			if tvb(offset+12,1):uint() ~= 0xff then if tvb(offset+12,1):uint() > 100 then subtree:add_le(apple_proximity_pairing_unpaired_charging_battery_level_1, tvb(offset+12,1), tvb(offset+12,1):uint()-128) else subtree:add_le(apple_proximity_pairing_unpaired_discharging_battery_level_1, tvb(offset+12,1), tvb(offset+12,1):uint()*-1) end else subtree:add_le(apple_proximity_pairing_unpaired_no_battery_level_1, tvb(offset+12,1)) end
			if tvb(offset+13,1):uint() ~= 0xff then if tvb(offset+13,1):uint() > 100 then subtree:add_le(apple_proximity_pairing_unpaired_charging_battery_level_2, tvb(offset+13,1), tvb(offset+13,1):uint()-128) else subtree:add_le(apple_proximity_pairing_unpaired_discharging_battery_level_2, tvb(offset+13,1), tvb(offset+13,1):uint()*-1) end else subtree:add_le(apple_proximity_pairing_unpaired_no_battery_level_2, tvb(offset+13,1)) end
			if tvb(offset+14,1):uint() ~= 0xff then if tvb(offset+14,1):uint() > 100 then subtree:add_le(apple_proximity_pairing_unpaired_charging_battery_level_3, tvb(offset+14,1), tvb(offset+14,1):uint()-128) else subtree:add_le(apple_proximity_pairing_unpaired_discharging_battery_level_3, tvb(offset+14,1), tvb(offset+14,1):uint()*-1) end else subtree:add_le(apple_proximity_pairing_unpaired_no_battery_level_3, tvb(offset+14,1)) end
			subtree:add_le(apple_proximity_pairing_lid_open_count, tvb(offset+15,1))
			subtree:add_le(apple_proximity_pairing_device_color, tvb(offset+16,1))
		---- Paired ----
		elseif tvb(offset+2,1):uint() == 0x01 then
			subtree:add_le(apple_proximity_pairing_utp, tvb(offset+5,1))
			battery_indication_1 = subtree:add(apple_proximity_pairing_battery_indication_1, tvb(offset+6,1), "Battery Indication 1")
			if tvb(offset+6,1):bitfield(0,4) ~= 0xf then battery_indication_1:add_le(apple_proximity_pairing_paired_battery_level_1, tvb(offset+6,1)) else battery_indication_1:add_le(apple_proximity_pairing_paired_no_battery_level_1, tvb(offset+6,1)) end
			if tvb(offset+6,1):bitfield(4,4) ~= 0xf then battery_indication_1:add_le(apple_proximity_pairing_paired_battery_level_2, tvb(offset+6,1)) else battery_indication_1:add_le(apple_proximity_pairing_paired_no_battery_level_2, tvb(offset+6,1)) end
			battery_indication_2 = subtree:add(apple_proximity_pairing_battery_indication_2, tvb(offset+7,1), "Battery Indication 2")
			battery_indication_2:add_le(apple_proximity_pairing_case_charging, tvb(offset+7,1))
			battery_indication_2:add_le(apple_proximity_pairing_right_charging, tvb(offset+7,1))
			battery_indication_2:add_le(apple_proximity_pairing_left_charging, tvb(offset+7,1))
			if tvb(offset+7,1):bitfield(4,4) ~= 0xf then battery_indication_2:add_le(apple_proximity_pairing_paired_battery_level_3, tvb(offset+7,1)) else battery_indication_2:add_le(apple_proximity_pairing_paired_no_battery_level_3, tvb(offset+7,1)) end
			subtree:add_le(apple_proximity_pairing_lid_open_count, tvb(offset+8,1))
			subtree:add_le(apple_proximity_pairing_device_color, tvb(offset+9,1))
			subtree:add_le(apple_proximity_pairing_encrypted_payload, tvb(offset+11,16))
		end
	end

	-------- Dissect Apple Hey Siri --------
	function dissect_apple_hey_siri(offset, lgth, tvb, tree)
		subtree = tree:add(apple_hey_siri, tvb(offset,lgth+2), "Apple \"Hey Siri\"")
		subtree:add_le(apple_hey_siri_perceptual_hash, tvb(offset+2,2))
		subtree:add_le(apple_hey_siri_snr, tvb(offset+4,1))
		subtree:add_le(apple_hey_siri_confidence, tvb(offset+5,1))
		subtree:add_packet_field(apple_hey_siri_device_class, tvb(offset+6,2), ENC_BIG_ENDIAN)
		subtree:add_le(apple_hey_siri_random_byte, tvb(offset+8,1))
	end

	-------- Dissect Apple AirPlay Target --------
	function dissect_apple_airplay_target(offset, lgth, tvb, tree)
		subtree = tree:add(apple_airplay_target, tvb(offset,lgth+2), "Apple AirPlay Target")
		subtree:add_le(apple_airplay_target_flags, tvb(offset+2,1))
		subtree:add_le(apple_airplay_target_config_seed, tvb(offset+3,1))
		subtree:add_packet_field(apple_airplay_target_ipv4_address, tvb(offset+4,4), ENC_BIG_ENDIAN)
	end

	-------- Dissect Apple AirPlay Solo Source --------
	function dissect_apple_airplay_solo_source(offset, lgth, tvb, tree)
		subtree = tree:add(apple_airplay_solo_source, tvb(offset,lgth+2), "Apple AirPlay Solo Source")
		subtree:add_le(apple_airplay_solo_source_data, tvb(offset+2,lgth))
	end

	-------- Dissect Apple Magic Switch --------
	function dissect_apple_magic_switch(offset, lgth, tvb, tree)
		subtree = tree:add(apple_magic_switch, tvb(offset,lgth+2), "Apple Magic Switch")
		subtree:add_le(apple_magic_switch_data, tvb(offset+2,2))
		subtree:add_le(apple_magic_switch_confidence_on_wrist, tvb(offset+4,1))
	end

	-------- Dissect Apple Handoff --------
	function dissect_apple_handoff(offset, lgth, tvb, tree)
		subtree = tree:add(apple_handoff, tvb(offset,lgth+2), "Apple Handoff")
		subtree:add_le(apple_handoff_version, tvb(offset+2,1))
		subtree:add_packet_field(apple_handoff_iv, tvb(offset+3,2), ENC_LITTLE_ENDIAN)
		subtree:add_le(apple_handoff_auth_tag, tvb(offset+5,1))
		subtree:add_le(apple_handoff_encrypted_payload, tvb(offset+6,10))
	end

	-------- Dissect Apple Tethering Target Presence
	function dissect_apple_tethering_target_presence(offset, lgth, tvb, tree)
		subtree = tree:add(apple_tethering_target_presence, tvb(offset,lgth+2), "Apple Tethering Target Presence")
		subtree:add_le(apple_tethering_target_presence_identifier, tvb(offset+2,4))
	end

	-------- Dissect Apple Tethering Source Presence --------
	function dissect_apple_tethering_source_presence(offset, lgth, tvb, tree)
		subtree = tree:add(apple_tethering_source_presence, tvb(offset,lgth+2), "Apple Tethering Source Presence")
		subtree:add_le(apple_tethering_source_presence_version, tvb(offset+2,1))
		flags = subtree:add(apple_tethering_source_presence_flags, tvb(offset+3,1), "Flags")
		flags:add_le(apple_tethering_source_presence_duplicate_uuids, tvb(offset+3,1))
		subtree:add_le(apple_tethering_source_presence_battery_level, tvb(offset+4,2))
		subtree:add_le(apple_tethering_source_presence_network_type, tvb(offset+6,1))
		subtree:add_le(apple_tethering_source_presence_signal_strength, tvb(offset+7,1))
	end

	-------- Dissect Apple Nearby Action --------
	function dissect_apple_nearby_action(offset, lgth, tvb, tree)
		offset_auth_tag=0
		subtree = tree:add(apple_nearby_action, tvb(offset,lgth+2), "Apple Nearby Action")
		flags = subtree:add(apple_nearby_action_flags, tvb(offset+2,1), "Flags")
		flags:add_le(apple_nearby_action_has_auth_tag, tvb(offset+2,1))
		flags:add_le(apple_nearby_action_needs_setup, tvb(offset+2,1))
		flags:add_le(apple_nearby_action_needs_keyboard, tvb(offset+2,1))
		flags:add_le(apple_nearby_action_needs_awdl, tvb(offset+2,1))
		flags:add_le(apple_nearby_action_needs_nan, tvb(offset+2,1))
		subtree:add_le(apple_nearby_action_type, tvb(offset+3,1))
		if tvb(offset+2,1):bitfield(0,1) == 0x1 then
			subtree:add_le(apple_nearby_action_auth_tag, tvb(offset+4,3))
			offset_auth_tag=3
		end

		---- Wi-Fi Password ----
		if tvb(offset+3,1):uint() == 0x08 and tvb(offset+1,1):uint() == 0x11 then
			nearby_action_parameters = subtree:add(apple_nearby_action_parameters, tvb(offset+offset_auth_tag+4,12), "Parameters")
			nearby_action_parameters:add_le(apple_nearby_action_wifi_password_hash_0, tvb(offset+offset_auth_tag+4,3))
			nearby_action_parameters:add_le(apple_nearby_action_wifi_password_hash_1, tvb(offset+offset_auth_tag+7,3))
			nearby_action_parameters:add_le(apple_nearby_action_wifi_password_hash_2, tvb(offset+offset_auth_tag+10,3))
			nearby_action_parameters:add_le(apple_nearby_action_wifi_password_hash_3, tvb(offset+offset_auth_tag+13,3))
		---- iOS Setup ----
		elseif tvb(offset+3,1):uint() == 0x09 and tvb(offset+1,1):uint() == 0x08 then
			nearby_action_parameters = subtree:add(apple_nearby_action_parameters, tvb(offset+offset_auth_tag+4,3), "Parameters")
			nearby_action_parameters:add_le(apple_nearby_action_ios_setup_device_class, tvb(offset+offset_auth_tag+4,1))
			nearby_action_parameters:add_le(apple_nearby_action_ios_setup_device_model, tvb(offset+offset_auth_tag+4,1))
			nearby_action_parameters:add_le(apple_nearby_action_ios_setup_device_color, tvb(offset+offset_auth_tag+5,1))
			nearby_action_parameters:add_le(apple_nearby_action_ios_setup_os_version, tvb(offset+offset_auth_tag+6,1))
		---- Repair ----
		elseif tvb(offset+3,1):uint() == 0x0a and tvb(offset+1,1):uint() == 0x07 then
			nearby_action_parameters = subtree:add(apple_nearby_action_parameters, tvb(offset+offset_auth_tag+4,2), "Parameters")
			repair_problem_flags = nearby_action_parameters:add(apple_nearby_action_parameters_repair_problem_flags, tvb(offset+offset_auth_tag+5,1), "Problem Flags")
			repair_problem_flags:add_le(apple_nearby_action_wifiperf, tvb(offset+offset_auth_tag+5,1))
			repair_problem_flags:add_le(apple_nearby_action_wifi, tvb(offset+offset_auth_tag+5,1))
			repair_problem_flags:add_le(apple_nearby_action_homekit, tvb(offset+offset_auth_tag+5,1))
			repair_problem_flags:add_le(apple_nearby_action_itunes, tvb(offset+offset_auth_tag+5,1))
			repair_problem_flags:add_le(apple_nearby_action_icloud, tvb(offset+offset_auth_tag+5,1))
		elseif tvb(offset+1,1):uint() > 2 then
			nearby_action_parameters = subtree:add(apple_nearby_action_parameters, tvb(offset+offset_auth_tag+4,lgth-6), "Parameters")
			nearby_action_parameters:add_le(apple_nearby_action_parameters_data, tvb(offset+offset_auth_tag+4,lgth-6))
		end
	end

	-------- Dissect Apple Nearby Info --------
	function dissect_apple_nearby_info(offset, lgth, tvb, tree)
		subtree = tree:add(apple_nearby_info, tvb(offset,lgth+2), "Apple Nearby Info")
		subtree:add_le(apple_nearby_info_activity_level, tvb(offset+2,1))
		nearby_info_information = subtree:add(apple_nearby_info_information, tvb(offset+3,1), "Information")
		nearby_info_information:add_le(apple_nearby_info_auto_unlock_enabled, tvb(offset+3,1))
		nearby_info_information:add_le(apple_nearby_info_auto_unlock_watch, tvb(offset+3,1))
		nearby_info_information:add_le(apple_nearby_info_watch_locked, tvb(offset+3,1))
		nearby_info_information:add_le(apple_nearby_info_has_auth_tag, tvb(offset+3,1))
		if tvb(offset+3,1):bitfield(3,1) == 0x1 then
			subtree:add_le(apple_nearby_info_auth_tag, tvb(offset+4,3))
		end
	end

	-------- Dissect Apple HomeKit Encrypted Notification --------
	function dissect_apple_homekit_encrypted_notification(offset, lgth, tvb, tree)
		subtree = tree:add(apple_homekit_encrypted_notification, tvb(offset,tvb(offset+1,1):bitfield(3,5)+2), "Apple HomeKit Encrypted Notification")
		subtree:add_le(apple_homekit_encrypted_notification_subtype, tvb(offset+1,1))
		subtree:add_le(apple_homekit_encrypted_notification_length, tvb(offset+1,1))
		subtree:add_le(apple_homekit_encrypted_notification_accessory_advertising_identifier, tvb(offset+2,6))
		subtree:add_le(apple_homekit_encrypted_notification_global_state_number, tvb(offset+8,2))
		subtree:add_packet_field(apple_homekit_encrypted_notification_characteristic_instance_id, tvb(offset+10,2), ENC_BIG_ENDIAN)
		subtree:add_le(apple_homekit_encrypted_notification_value, tvb(offset+12,8))
		subtree:add_le(apple_homekit_encrypted_notification_auth_tag, tvb(offset+20,4))
	end

	-------- Dissect Apple Continuity Undecoded Message --------
	function dissect_apple_continuity_undecoded_message(offset, lgth, tvb, tree)
		subtree = tree:add(apple_continuity_undecoded_message, tvb(offset,lgth+2), "Apple Continuity Undecoded Message")
		subtree:add_le(apple_continuity_undecoded_message_type, tvb(offset,1))
		subtree:add_le(apple_continuity_undecoded_message_length, tvb(offset+1,1))
		continuity_undecoded_message_data = subtree:add_le(apple_continuity_undecoded_message_data, tvb(offset+2,lgth))
		continuity_undecoded_message_data:add_proto_expert_info(btcommon_eir_ad_entry_data_undecoded, "Undecoded")
	end

	-------- Undecoded Apple Data --------
	function undecoded_apple_data(tvb, pinfo, tree)
		pinfo.cols.protocol = "HCI_EVT"
		subtree = tree:add_le(btcommon_eir_ad_entry_data, tvb())
		subtree:add_proto_expert_info(btcommon_eir_ad_entry_data_undecoded, "Undecoded")
	end

	-------- Length Apple Continuity Message --------
	function length_apple_continuity_message(offset, tvb)
		if tvb(offset,1):uint() == 0x06 or tvb(offset,1):uint() == 0x11 then return tvb(offset+1,1):bitfield(3,5) else return tvb(offset+1,1):uint() end
	end

	-------- Check Apple Continuity advertising payload format --------
	function check_apple_continuity_advertising_payload_format(offset, tvb, pinfo, tree)
		while offset < tvb:len() do
			status, lgth = pcall(length_apple_continuity_message, offset, tvb)
			if not status then return false end
			offset = offset + 2 + lgth
		end
		if offset == tvb:len() then return true else return false end
	end

	-------- Apple Continuity Dissector --------
	function apple_continuity_protocol.dissector(tvb, pinfo, tree)
		offset = 0
		if tvb:len() == 0 then return end
		if check_apple_continuity_advertising_payload_format(offset, tvb, pinfo, tree) == false then undecoded_apple_data(tvb, pinfo, tree) return else tree:add_le(apple_continuity_protocol, tvb(), "Apple Continuity"):set_hidden() end
		pinfo.cols.protocol = apple_continuity_protocol.name

		while offset < tvb:len() do
			lgth = length_apple_continuity_message(offset, tvb)

			-------- Apple Reserved --------
			if tvb(offset,1):uint() == 0x00 then
				if not pcall(dissect_apple_reserved, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Hash --------
			elseif tvb(offset,1):uint() == 0x01 then
				if not pcall(dissect_apple_hash, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple iBeacon --------
			elseif tvb(offset,1):uint() == 0x02 and lgth == 0x15 then
				if not pcall(dissect_apple_ibeacon, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple AirPrint --------
			elseif tvb(offset,1):uint() == 0x03 and lgth == 0x16 then
				if not pcall(dissect_apple_airprint, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- AppleTV Setup --------
			elseif tvb(offset,1):uint() == 0x04 then
				if not pcall(dissect_appletv_setup, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple AirDrop --------
			elseif tvb(offset,1):uint() == 0x05 and lgth == 0x12 then
				if not pcall(dissect_apple_airdrop, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple HomeKit --------
			elseif tvb(offset,1):uint() == 0x06 and (lgth == 13 or lgth == 17) then
				if not pcall(dissect_apple_homekit, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Proximity Pairing --------
			elseif tvb(offset,1):uint() == 0x07 and ((lgth == 0x0f and tvb(offset+2,1):uint() == 0x00) or (lgth == 0x19 and tvb(offset+2,1):uint() == 0x01)) then
				if not pcall(dissect_apple_proximity_pairing, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Hey Siri --------
			elseif tvb(offset,1):uint() == 0x08 and lgth == 0x07 then
				if not pcall(dissect_apple_hey_siri, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple AirPlay Target --------
			elseif tvb(offset,1):uint() == 0x09 and lgth == 0x06 then
				if not pcall(dissect_apple_airplay_target, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple AirPlay Solo Source --------
			elseif tvb(offset,1):uint() == 0x0a then
				if not pcall(dissect_apple_airplay_solo_source, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Magic Switch --------
			elseif tvb(offset,1):uint() == 0x0b and lgth == 0x03 then
				if not pcall(dissect_apple_magic_switch, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Handoff --------
			elseif tvb(offset,1):uint() == 0x0c and lgth == 0x0e then
				if not pcall(dissect_apple_handoff, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Tethering Target Presence
			elseif tvb(offset,1):uint() == 0x0d and lgth == 0x04 then
				if not pcall(dissect_apple_tethering_target_presence, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Tethering Source Presence --------
			elseif tvb(offset,1):uint() == 0x0e and lgth == 0x06 then
				if not pcall(dissect_apple_tethering_source_presence, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Nearby Action --------
			elseif tvb(offset,1):uint() == 0x0f and lgth >= 2 then
				if not pcall(dissect_apple_nearby_action, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Nearby Info --------
			elseif tvb(offset,1):uint() == 0x10 and lgth >= 2 then
				if not pcall(dissect_apple_nearby_info, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple HomeKit Encrypted Notification --------
			elseif tvb(offset,1):uint() == 0x11 and lgth == 22 then
				if not pcall(dissect_apple_homekit_encrypted_notification, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end

			-------- Apple Continuity Undecoded Message --------
			else
				if not pcall(dissect_apple_continuity_undecoded_message, offset, lgth, tvb, tree) then undecoded_apple_data(tvb, pinfo, tree) break end
			end

			offset = offset + 2 + lgth
		end
	end

	-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	ble_dis_table = DissectorTable.get("btcommon.eir_ad.manufacturer_company_id")
	ble_dis_table:add(0x0006,microsoft_cdp_protocol) -- Microsoft Connected Devices Platform (CDP) --
	ble_dis_table:add(0x004c,apple_continuity_protocol) -- Apple Continuity --
	ble_dis_table:add(0x0087,garmin_ble_protocol) -- Garmin BLE --

end