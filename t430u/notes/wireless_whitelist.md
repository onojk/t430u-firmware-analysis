# T430u Wireless Whitelist Analysis

## Module
- **File**: `LenovoWmaPolicyDxe.efi`  (extracted from the 4MB BIOS dump)
- **GUID**: `79E0EDD7-9D1D-4F41-AE1A-F896169E5216`
- **Size**: 8,032 bytes
- **Type**: PE32+ x86-64 EFI Boot Service Driver
- **Module name**: WMA Policy DXE (Wireless Management Authentication)

## Entry point
The driver registers a callback with the UEFI BootServices.
- `entry()` calls `BootServices->LocateProtocol` three times (offsets 0x418, 0x4b8, 0x4e8 are protocol GUIDs in the data section)
- Then registers `FUN_00000fa8` as a notification callback via what appears to be `RegisterProtocolNotify`
- The actual whitelist enforcement runs when that callback fires

## Whitelist data location
- **File offset**: 0x294
- **Length**: 30 entries × 12 bytes = 360 bytes
- **Format**: each entry is `<VID:DID> <SubsysVID:SubsysDID> <Type:uint32>`
- **Referenced by**: `FUN_00000ae0` (the comparison function — reads the table twice)

## Decoded whitelist

### PCI Mini-PCIe wireless cards (Type 0x00, 13 entries)

| VID:DID | Subsys | Card |
|---------|--------|------|
| 10EC:8176 | 10EC:8195 | Realtek RTL8188CE 802.11n |
| 14E4:0576 | 14E4:0576 | Broadcom Wireless |
| 8086:0089 | 8086:1311 | Intel Centrino Advanced-N 6205 |
| 8086:0089 | 8086:1316 | Intel Centrino Advanced-N 6205 |
| 8086:4238 | 8086:1111 | Intel Centrino Ultimate-N 6300 |
| 8086:0085 | 8086:1311 | Intel Centrino Advanced-N 6205 (2x2) |
| 8086:0890 | 8086:4022 | Intel Centrino Wireless-N 2200 |
| 8086:0891 | 8086:4222 | Intel Centrino Wireless-N 2230 |
| 8086:0084 | 8086:1315 | Intel Centrino Wireless-N 1000 |
| 14E4:4727 | 14E4:0609 | Broadcom BCM4313 |
| 14E4:4727 | 14E4:0608 | Broadcom BCM4313 |
| 14E4:4359 | 14E4:0607 | Broadcom BCM43228 dual-band |
| 14E4:4365 | 17AA:0611 | Broadcom BCM43142 |

### USB-attached (Bluetooth, WiMax, WWAN — 17 entries)

| VID:DID | Type | Device |
|---------|------|--------|
| 8086:0888 | 0x05 | Intel Centrino Wireless-N 130 |
| 0A5C:21F4 | 0x05 | Broadcom Bluetooth USB |
| 0A5C:21F3 | 0x05 | Broadcom Bluetooth USB |
| 8087:07DA | 0x05 | Intel Centrino Bluetooth USB |
| 04CA:2007 | 0x05 | Lite-On Bluetooth USB |
| 105B:E065 | 0x05 | Foxconn Bluetooth USB |
| 8086:0187 | 0x05 | Intel WiMax/WiFi 6250 USB |
| 10EC:8176 | 0x01 | Realtek RTL8188CE (USB variant) |
| 05C6:920D | 0x01 | Qualcomm Gobi 9x15 (WWAN) |
| 1199:9012 | 0x01 | Sierra Wireless EM7305 LTE |
| 1199:9013 | 0x01 | Sierra Wireless MC7710 HSPA+ |
| 0BDB:1927 | 0x01 | Ericsson F5521gw HSPA+ |
| 0BDB:1926 | 0x01 | Ericsson F5521gw HSPA+ |
| 0BDB:1931 | 0x01 | Ericsson H5321gw HSPA+ |
| 0BDB:1930 | 0x01 | Ericsson H5321gw HSPA+ |
| 1199:68A8 | 0x01 | Sierra Wireless MC8355 Gobi 3000 |
| 1199:68A9 | 0x06 | Sierra Wireless MC8775 |

## Notable absences
- No Atheros / Qualcomm 802.11 cards
- No Ralink / MediaTek
- No 7260/AC8260/AX2xx Intel (post-Ivy Bridge cards)
- No third-party non-Lenovo subsystem IDs

## Patching strategy (theoretical)
Three approaches to defeat the whitelist:

1. **Add target card's VID:DID to the table** — find a 12-byte free slot or replace an unused entry
2. **Patch `FUN_00000ae0` to always return success** — modify the comparison/result code
3. **Patch the entry point to skip protocol registration** — disable the callback entirely

Approach 1 is least invasive. Approach 2 is what most ThinkPad whitelist mods do.

Either way: the patched module needs to be re-inserted into the BIOS image, the BIOS image flashed back to the chip externally (since the BIOS won't let you flash a modified version internally — that's another protection in `LenovoSecuritySmiDispatch`).
