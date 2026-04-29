# T430u SVP Manager (SMM-side) Module Analysis

## Module
- **File**: `LenovoSvpManagerSmm.efi` (extracted from the 4MB BIOS dump)
- **Size**: 3,712 bytes
- **Type**: PE32+ x86-64, declared as "EFI runtime driver" but loaded as SMM (per its DXE depex placement)
- **Module name**: SVP Manager SMM — the SMM peer of `LenovoSvpManagerDxe.efi`

## Big picture

This module is the **producer** of the SVP storage protocol (`82B244DC-...`). The DXE-side bridge we analyzed previously is its consumer. The bytes for `82B244DC-...` are present at offset `0x480` of this module's data section, which is exactly the pattern of a producer — only the module that calls `InstallProtocolInterface` needs to embed the GUID locally for the API call.

That confirms the structural prediction we made earlier: the producer of SVP storage authority lives in SMM, where it should.

The module is small. Only six real functions, plus four tiny helpers. Nearly every function is a thin wrapper around a single call into another protocol. **There's almost no logic here** — this module is a router. It reads SVP bytes from the EC, validates the trailing checksum, exposes a `read()` to other SMM/DXE consumers, and updates a status flag stored in EFI variables.

## Strings

Two UTF-16 strings, no others:

| Offset | String | Role |
|---|---|---|
| `0x4C0` | `LenovoScratchData` | Same EFI variable as in the DXE peer — shared transient state |
| `0x4E8` | `LenovoSecurityConfig` | New — likely holds persistent SVP/lockout/retry state |

`LenovoSecurityConfig` is a meaningful new finding. The DXE side never named it; it appeared only here. Likely candidates for what's stored in it:
- "SVP is set" flag
- Failed-attempt counter (the thing that triggers the `0199` retry-exceeded error from the DXE side)
- Lockout state

Searching the BIOS for other modules that read/write `LenovoSecurityConfig` would map the lockout subsystem.

## GUIDs in the data section

23 GUIDs total, several with known meanings:

### Protocol/event GUIDs already seen elsewhere
- `0x3B0` — `13DC32CC-A8DF-425A-B775-F16C14B9C7D1` (shared with DXE peer + PasswordCp)
- `0x3C0` — `2846B2A8-77C8-4432-86EC-199F205D37CA` (shared)
- `0x3D0` — `65FB555D-5CCA-40C3-9967-227988288DD8` (shared)
- `0x3E0` — `73E47354-B0C5-4E00-A714-9D0D5A4FDBFD` (shared)
- `0x3F0` — `FE2965BB-5A8E-43B3-AEDD-ABCC63003D14` (PasswordCp)
- `0x400` — `293D0637-6A70-4B4B-B333-7571C79EBEF6` (PasswordCp)
- `0x410` — `56350810-2CB2-4AA0-96D2-66D1B8E1AAC2` (PasswordCp UI/render)
- `0x420` — `E01FC710-BA41-493B-A919-53583368F6D9` ★ **Stage 2 hash protocol (the password-hash protocol the PasswordCp module uses)**
- `0x430` — `2CF8CC1B-58DF-4646-8DEE-7CEFAB10F782` (setup browser)
- `0x440` — `B2D39F58-0D08-41AF-8CA0-AF728BCC02A7` (event/notify GUID seen in DXE peer)
- `0x480` — **`82B244DC-8503-454B-A96A-D0D2E00BF86A`** ★ **SVP storage protocol — produced here**
- `0x490` — `0DE8BACF-E00A-4538-BE0D-81AF9374FCC9` (variable storage proto)

### Standard EFI GUIDs (recognizable)
- `0x2B0` — `5B1B31A1-9562-11D2-8E3F-00A0C969723B` = **EFI_LOADED_IMAGE_PROTOCOL_GUID**

That last one is a giveaway. The module looks itself up via LoadedImageProtocol — typical pattern for getting your own ImageHandle for later UnloadImage or for accessing your own loader info.

### Lenovo-proprietary GUIDs (unknown, probably internal)
Many: `0x2A0 BC62157E-...`, `0x2C0 4C8A2451-...`, `0x2D0 3BCE1D9F-...`, etc. They're the SMM-side protocols (SmmAccess, SmmCpu, SmmIoTrap, SmmBase, etc.) that this module needs to do its work.

### **The hash protocols' presence**

The Stage 2 hash protocol GUID (`E01FC710-...`) **is in this module's data section** at offset `0x420`. That tells us this module *consumes* (LocateProtocol) the stage-2 hash, but doesn't produce it.

The Stage 1 hash protocol GUID (`E3ABB023-...`) is **not in this module's data**. So whoever produces stage 1 is a different module entirely. Most likely candidate: `LenovoCryptServiceSmm.efi` (named appropriately, and it's a known consumer of the SVP storage protocol from our earlier consumer-graph analysis).

## Function map

```
LenovoSvpManagerSmm.efi
├── entry(ImageHandle, SmmSystemTable)
│   ├── FUN_00000a8c  ← initialization helper
│   │   ├── stash SystemTable + RT/BS pointers in globals
│   │   ├── LocateProtocol(0x2F0 GUID)
│   │   ├── LocateProtocol(0x2E0 GUID)
│   │   ├── LocateProtocol(0x2B0 GUID)  ← LoadedImageProtocol — get our own image record
│   │   ├── call image->LoadOptions handler if present
│   │   └── LocateProtocol(0x290 — Lenovo proprietary)
│   ├── if init failed: bail
│   ├── RegisterProtocolNotify(GUID@0x3c0, ...)
│   ├── LocateProtocol(GUID@0x4b0 = 9F5E8C5E-0373-4A08-8DB5-1F913316C5E4)
│   │   → DAT_00000d20 (an SMI/handler-registration protocol)
│   ├── DAT_00000d20->func0(self, command_id=5, handler=FUN_00000520)
│   │   → registers FUN_00000520 as the handler for SVP storage operations
│   ├── LocateProtocol(0x370 GUID) → DAT_00000dc0
│   ├── LocateProtocol(0x4a0 GUID = 0DE8BACF — variable storage)
│   │   → DAT_00000db8 (used heavily by FUN_00000830)
│   ├── LocateProtocol(0x3e0 GUID) → DAT_00000d28
│   ├── FUN_00000984 — tiny init helper that calls FUN_00000c84 with a 10-byte buffer
│   └── FUN_00000830 — reads the stored SVP block and validates checksum
│
├── FUN_00000520  ← THE REGISTERED HANDLER (the actual SVP service)
│                    Called when other modules invoke the SVP storage protocol
│
├── FUN_000006a8  ← getter: returns the lockout/retry state byte
│                    Reads DAT_00000DA0 (status word) and returns it
│
├── FUN_000006B4  ← writer / state-mutation handler (large function)
│                    Branches on a small command code, manipulates state vars at
│                    DAT_00000DA0/DA4/DA8, calls back into the EC interface
│
├── FUN_00000830  ← read & checksum SVP block from EC EEPROM
│   ├── Loop: for each byte 0..15:
│   │   ├── DAT_00000DB8->func0(self, 0x57, offset, &output)
│   │   │     ← THE 0x57 PROTOCOL — the same EC subcommand we saw in the DXE peer
│   │   ├── store byte in DAT_00000D80[i]
│   │   └── add to running 16-bit sum BX
│   ├── Read byte at offset 0x57 - 0x55 = 0x02 (a different sub-command, fetches the trailing checksum byte)
│   ├── Compare AL (stored magic) vs BL (computed sum):
│   │   ├── if equal and byte != 0:  set DAT_00000DA0 |= 1   (valid)
│   │   ├── if (BL - 0x56) == AL:    set DAT_00000DA0 |= 1   (alt valid form)
│   │   └── else: re-zero buffer and return without setting valid flag
│   └── return 0
│
├── FUN_00000930  ← reads a status byte at the password-history protocol
│                    Calls protocol@0xDC0 (the GUID@0x370 protocol) with size 0x80,
│                    pulls byte at offset 0x35, returns 0 or 1
│                    This is reading retry-counter / lockout state
│
├── FUN_00000A38  ← state aggregator
│   ├── FUN_000006A8(...)  → AL bit 0 = "valid SVP loaded" 
│   ├── FUN_00000930()     → AL = retry/lockout flag
│   ├── combine into EBX:
│   │   bit 0: valid loaded  (from 6A8)
│   │   bit 1: lockout active
│   │   bit 2: SVP set       (from 930)
│   │   bit 3: secondary lockout
│   └── return EBX
│
└── helpers:
    FUN_00000c84(buf, len)         ← ZeroMem
    FUN_00000c9c(buf, val, len)    ← SetMem
    FUN_00000984                   ← inits a 10-byte buffer at DAT_00000D30 to zero
```

## The 0x57 sub-command, again

`FUN_00000830` is unambiguous: it issues the same **`0x57`** sub-command we saw the DXE peer use, then issues **`0x57 - 0x55 = 0x02`** to fetch the trailing byte separately. The 0x57 is reading data bytes, the 0x02 is reading the checksum/status byte.

This is the same protocol the DXE side calls — but here we see the implementation side. The protocol DAT_00000DB8 (located via the `0DE8BACF-...` variable storage GUID) is what owns the actual EC communication path. So that protocol — which we've now seen referenced from 50+ modules — is the actual EC bridge.

That is a substantive find. The protocol GUID `0DE8BACF-E00A-4538-BE0D-81AF9374FCC9` was originally guessed to be "variable storage" based on its similar use in the DXE peer. We can now upgrade that guess to: **"Lenovo EC mailbox / EEPROM I/O protocol."** It exposes a single function pointer that takes (sub_command, byte_offset, &buffer) and brokers EC reads/writes. The likely producer of this protocol is `LenovoMailBoxSmm.efi` or `LenovoEcService.efi`, both visible in the consumer graph.

## What this module does (summary)

Step by step, in plain English:

1. At driver load, the module walks a list of dependencies and retrieves their protocol pointers.
2. It registers itself as a callback target via the SMI-handler registration protocol (the 9F5E8C5E protocol at 0x4B0). Other code wanting SVP services calls into command-id-5 of that handler registry, which routes to `FUN_00000520` here.
3. At init, it reads the 16-byte SVP storage block from the EC via the 0x57 sub-command, plus its trailing checksum byte via sub-command 0x02. It stores the result in `DAT_00000D80` and sets a valid-flag in `DAT_00000DA0` if the checksum matches one of two acceptable forms.
4. From then on, when any module calls the SVP service, this module's handler at `FUN_00000520` (and its helper `FUN_00000A38`) returns the cached state, performs lockout checks, and brokers further reads/writes back into the EC.

## What this module does NOT do

- **It does not compute the password hash.** The hashing is delegated to the Stage 2 hash protocol (GUID `E01FC710-...`), whose GUID is in this module's data only because *some other module* hands the typed-password digest to this service for comparison against the stored value.
- **It does not own the EC EEPROM directly.** The EC mailbox protocol (`0DE8BACF-...`) does. This module is a client of that protocol.
- **It does not display anything.** No strings, no calls into ConOut. The user-visible 0177 / 0199 errors come from the DXE peer.
- **It does not implement A/B-block redundancy.** The DXE peer does that across two reads of this module's service.

## What we now know about the SVP architecture, end to end

```
USER TYPES PASSWORD
  ↓
LenovoPasswordCp.efi
  ↓ (validates charset, builds buffer)
  ↓ stage-1 hash (E3ABB023-...) — implementer module unknown, candidate: LenovoCryptServiceSmm
  ↓ stage-2 hash (E01FC710-...) — implementer module unknown, candidate: LenovoCryptServiceSmm
  ↓ produces 16-byte digest
  ↓
LenovoSvpManagerDxe.efi
  ↓ (validates A/B blocks, manages 0177 / 0199 error display)
  ↓ calls SVP storage protocol (82B244DC-...) — the consumer side
  ↓
SMI bridge
  ↓
LenovoSvpManagerSmm.efi (THIS MODULE)
  ↓ (cached storage block + lockout state, gated through this module's handler)
  ↓ calls Lenovo EC Mailbox protocol (0DE8BACF-...) — the actual EC speak
  ↓
LenovoMailBoxSmm.efi or LenovoEcService.efi
  ↓ (runs the actual EC command sequence)
  ↓
EC EEPROM
```

That's a pretty clear architectural map for what was, until two days ago, a black box.

## Threads to pull next

The cleanest direction is **`LenovoCryptServiceSmm.efi`**. It's named like the place crypto primitives live. It's a known consumer of the SVP storage protocol (from our cross-reference). It's the most likely module to install both the stage-1 and stage-2 hash protocols. Extracting and reading it would close the loop on "what algorithm hashes the password."

After that, **`LenovoMailBoxSmm.efi`**: confirming that it's the producer of the `0DE8BACF-...` EC mailbox protocol would let us see the actual EC command sequences, the I/O ports used, and the subset of EC RAM regions accessible to BIOS code.

Both are small, focused modules. Each is one session's work.

## What this isn't

A jailbreak path or a vulnerability disclosure. We've mapped the architecture; we have not bypassed any check. Even with full knowledge of "the SVP storage protocol exists and is implemented by this module," the protocol itself is locked behind an SMI bridge that runs in a higher privilege ring than anything we can attack from userspace or even the OS kernel. The point continues to be comprehension — what the silicon and the firmware are actually doing.
