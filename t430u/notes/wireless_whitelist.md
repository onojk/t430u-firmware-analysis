# T430u Wireless Whitelist Analysis

## Module
- **File**: `LenovoWmaPolicyDxe.efi`  (extracted from the 4MB BIOS dump)
- **GUID**: `79E0EDD7-9D1D-4F41-AE1A-F896169E5216`
- **Size**: 8,032 bytes
- **Type**: PE32+ x86-64 EFI Boot Service Driver
- **Module name**: WMA Policy DXE — "Wireless Management Authentication"

## Big picture

This driver implements the infamous ThinkPad whitelist: the `1802: Unauthorized network card is plugged in` boot error. It runs early in boot, registers a callback, and when wireless hardware is enumerated the callback compares the card's VID/DID against an internal table. Cards not on the table get rejected with a screen full of red.

The whole thing is about 8 KB of x86-64. There are four functions worth knowing about:

| Function | Role |
|---|---|
| `entry()` | UEFI driver entry. Locates protocols, registers `FUN_00000fa8` as a callback, returns. |
| `FUN_00000fa8` | The callback. Fires on hardware enumeration. Reads device IDs, calls the comparison. |
| `FUN_00000ae0` | The whitelist comparison. Walks the table, returns success or error. |
| `FUN_000009cc` | The error-display routine. Builds the "1802: Unauthorized..." message and prints it. |

## Whitelist data location
- **File offset**: `0x294` (the dword at `0x290` is the loop pointer / type field)
- **Length**: 30 entries × 12 bytes = 360 bytes
- **Format**: `<VID:uint16> <DID:uint16> <SubsysVID:uint16> <SubsysDID:uint16> <Type:uint32>`
- **Sentinel**: an entry with `Type == 0x06` terminates the scan loop
- **Referenced by**: `FUN_00000ae0` at `0x00000b03` and `0x00000b8f` (the two scan-loop heads)

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

### USB-attached devices (Bluetooth, WiMax, WWAN — 17 entries)

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

The last entry's Type field of `0x06` doubles as the loop sentinel — convenient, since this entry is at the end of the table anyway.

## Notable absences
- No Atheros / Qualcomm 802.11 cards
- No Ralink / MediaTek
- No 7260 / AC8260 / AX2xx Intel cards (post-Ivy-Bridge)
- No third-party non-Lenovo subsystem IDs

This is why putting a modern WiFi 6 card in a T430u produces the 1802 error — its VID/DID is not on the list and never can be without modifying the BIOS.

## Code flow — end to end

### Step 1: driver registration

`entry()` at `0x00001074`:

```
LEA   RCX, [0x418]                 ; first protocol GUID (in module's own data)
CALL  [BootServices + 0x140]       ; offset 0x140 in BootServices = LocateProtocol
... two more LocateProtocol calls for GUIDs at 0x4b8 and 0x4e8 ...
LEA   RDX, [FUN_00000fa8]          ; address of the callback
CALL  [BootServices + 0x80]        ; some BootServices function — likely RegisterProtocolNotify
RET
```

The driver does not do the comparison itself at load time. It just hands a callback to UEFI and exits.

### Step 2: the callback fires

`FUN_00000fa8` at `0x00000fa8` runs each time hardware is enumerated. The key block:

```
00000fea  MOV   CL, 0x50
00000fec  TEST  AL, 0x4               ; check a status bit
00000fee  JZ    LAB_00001027          ; bit clear → no device, take other branch
00000ff0  CALL  FUN_00000c24          ; bit set → read VID/DID from hardware
                                       ; returns the VID:DID dword in EAX
00000fff  XOR   ECX, ECX              ; param_1 = 0 (image handle, unused here)
00001003  MOV   [RSP+0x40], EAX       ; stash VID/DID on the stack
00001007  CALL  FUN_00000ae0          ; ← whitelist comparison
0000100c  TEST  RAX, RAX
0000100f  JS    LAB_00001067          ; RAX is signed — high bit set means EFI error
                                       ; (sign flag set ↔ no-match)
                                       ; jump to function exit
00001011  ...                         ; match path: store info, continue boot
```

So the callback hands the candidate VID/DID to `FUN_00000ae0` and reacts to the return code.

### Step 3: the comparison

`FUN_00000ae0` at `0x00000ae0` is the gatekeeper.

**Arguments:**
- `param_1` (RCX) — image handle; not used in the logic
- `param_2` (EDX) — comparison mode flag (0=PCI, 1 or 5=USB, anything else=skip)
- `param_3` (R8) — pointer to the candidate's VID/DID structure

**Dispatch:**

```
00000ae7  TEST  EDX, EDX
00000ae9  JZ    LAB_00000b8f         ; mode==0 → PCI loop (compares VID/DID + Subsys)
00000af2  SUB   EDX, 1
00000af5  JZ    LAB_00000b03         ; mode==1 → USB loop
00000af7  CMP   EDX, 4
00000afa  JZ    LAB_00000b03         ; mode==5 → USB loop
00000afc  XOR   EAX, EAX
00000afe  JMP   LAB_00000b8a         ; else → return 0 (no enforcement)
```

The mode argument is the same {0, 1, 5, 6} space as the Type field in the table, which is consistent.

**The two scan loops:**

The PCI loop (LAB_00000b8f) compares each entry's VID:DID against `[R11]`, AND each entry's Subsys VID:DID against `[R11+4]`. Both must match. The USB loop (LAB_00000b1c onward) compares VID:DID only.

Both loops walk the table 12 bytes at a time, checking Type field for the `0x06` sentinel to know when to stop.

**Outcome paths — important correction from initial reading:**

```
LAB_00000bf9  ← MATCH FOUND
  CMP   [DAT_00001e18], R9B          ; "first match seen" flag
  JNZ   LAB_00000c1a                  ; already matched once → skip notification
  CALL  FUN_00000930                  ; first match → notify (probably SMM handler)
  MOV   byte ptr [DAT_00001e18], 0x1  ; set the flag
LAB_00000c1a:
  MOV   RAX, R9                       ; return value from FUN_00000930
  JMP   LAB_00000b8a                  ; → function exit (success)

LAB_00000b63  ← NO MATCH (loop fell off end at sentinel)
  MOV   RCX, R11                      ; pass the candidate VID:DID
  CALL  FUN_000009cc                  ; ← display the 1802 error message
  TEST  RAX, RAX
  JNS   LAB_00000b80                  ; if display succeeded
  MOV   [RSP+local_res10], 0x1
LAB_00000b78:
  MOV   EAX, [RSP+local_res10]
  TEST  EAX, EAX
  JNZ   LAB_00000b78                  ; ← infinite loop! "halt the boot here"
LAB_00000b80:
  MOV   RAX, -0x7ffffffffffffff9      ; 0x8000000000000007 = EFI error
  JMP   LAB_00000b8a                  ; → function exit (failure)
```

The infinite loop at `0x00000b78` is the giveaway — when the card is unauthorized, the BIOS doesn't just return an error code, it deliberately hangs the boot. That's the behavior every ThinkPad owner who has ever seen the 1802 error remembers: the message appears, and the machine refuses to do anything else.

### Step 4: the error message

`FUN_000009cc` at `0x000009cc` is the cosmetic part — building the visible string.

```
LEA   RCX, [0x408]                ; protocol GUID (likely text-output / setup browser)
CALL  [BootServices + 0x140]      ; LocateProtocol
...
; format the device IDs into a string buffer:
LEA   R8, [u"%04x/%04x"]          ; or "%04x/%04x/%04x/%04x" for full subsys
CALL  FUN_00001674                ; sprintf-equivalent
...
LEA   R8, [u"1802: Unauthorized network card is plugged in..."]   ; at 0x510
CALL  FUN_00001674                ; build the full message
...
CALL  [RAX+0x8]                   ; show it on screen
```

The literal string lives in the module's data section at offset `0x510`, encoded as UTF-16. The full text (visible to Ghidra's analysis but truncated in the disassembly view) is:

> `1802: Unauthorized network card is plugged in - Power off and remove the miniPCI network card (xxxx/xxxx/xxxx/xxxx).`

Where the `xxxx` slots are filled in with the offending card's VID/DID/SubsysVID/SubsysDID. That's why the error message has always been so specific: it tells you exactly which card it just rejected.

## Patch points (theoretical)

If one were modifying this driver — which we are not — three byte sequences are interesting:

**1. The infinite loop at `0x00000b78`** (`75 f8` = `JNZ -8`):
Replacing `75 f8` with `90 90` (two NOPs) breaks the deliberate hang. Boot would still proceed past the 1802 message instead of stopping forever. Smallest possible patch (2 bytes).

**2. The error display call at `0x00000b66`** (`e8 61 fe ff ff` = `CALL FUN_000009cc`):
Replacing all 5 bytes with `90` × 5 prevents the 1802 message from being displayed at all. The BIOS would still return an error to the caller, but no screen message, no halt.

**3. The sign-test branch at `0x0000100f` in `FUN_00000fa8`** (`78 56` = `JS +0x56`):
Replacing `78 56` with `90 90` makes the callback ignore the comparison's return code. The unauthorized card path is never taken. Whitelist effectively bypassed.

The cleanest single-instruction defeat is probably #3 — two bytes in the callback. But this is the kind of modification that requires re-flashing the BIOS externally (since the BIOS itself would refuse to write a modified copy of itself — that's a separate protection in the SMM modules).

## Cross-references summary

```
LenovoWmaPolicyDxe.efi
├── entry()                           ← UEFI loader entry point
│   └── registers FUN_00000fa8 via BootServices
│
├── FUN_00000fa8 (callback)           ← fires on hardware enumeration
│   ├── FUN_00000c24                  ← reads device VID/DID
│   ├── FUN_00000ae0                  ← whitelist check (success/fail return)
│   └── FUN_00000c84                  ← post-check handling
│
├── FUN_00000ae0 (whitelist check)
│   ├── reads table at DAT_00000290   ← the 30-entry table
│   ├── FUN_00000930 (on match)       ← SMM notification?
│   └── FUN_000009cc (on no-match)    ← display 1802 error
│
└── FUN_000009cc (error display)
    ├── format strings at 0x5f0, 0x618 ("%04x/%04x[/%04x/%04x]")
    ├── 1802 message string at 0x510
    └── FUN_00001674                   ← sprintf-equivalent
```

Three more functions remain unread in this module (`FUN_00000930`, `FUN_00000c84`, `FUN_00001994`, plus the SMM-notification path). They are unlikely to change the picture above but are worth touching when convenient.

## What this isn't

This document explains how a piece of OEM firmware works. It is not a tool for bypassing it, and does not include a patched module, a binary diff, or instructions for re-flashing. The intent is comprehension: knowing what the silicon is doing and why.
