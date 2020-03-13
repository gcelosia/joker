# Joker
A Wireshark dissector for Bluetooth Low Energy (BLE) advertisement packets of Apple Continuity, Microsoft CDP and Garmin proprietary protocols.

## Prerequisite
Make sure the version of Wireshark you have installed was compiled with Lua support (see https://wiki.wireshark.org/Lua).

## Install
1. If Wireshark is running, stop Wireshark
2. mkdir -p ~/.config/wireshark/plugins
3. cp joker.lua ~/.config/wireshark/plugins/
4. Run Wireshark 
5. If needed, reload Lua plugins by clicking Analyze -> Reload Lua Plugins (or Ctrl+Maj+L)