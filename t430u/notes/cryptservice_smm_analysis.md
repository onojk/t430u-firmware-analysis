# T430u Crypto Service (SMM-side) Module Analysis

## Module
- **File**: `LenovoCryptServiceSmm.efi`
- **Size**: 3,904 bytes
- **Type**: PE32+ x86-64, EFI runtime/SMM driver
- **Role**: **Producer of stage-1 and stage-2 password hash protocols** — but NOT the actual implementer of the hash math

## Headline finding

This module is the producer of both `E3ABB023-...` (stage-1) and `E01FC710-...` (stage-2)
password hash protocols. The GUIDs are at offsets `0x4E0` and `0x4C0` of the module's data
section. That confirms the structural prediction.

But here's the surprise: **this module does not contain any actual hash algorithm code.**
It's a thin shim. Roughly 200 bytes of code each for the two hash entry points, all of which
delegates to a deeper service — a Lenovo proprietary "HashService" protocol identified by
GUID `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE`, which is itself located via another protocol
identified by GUID `69188A5F-6BBD-46C7-9C16-55F194BEFCDF`.

The actual cryptographic primitive lives one layer deeper, in a module we have not yet
located. Most likely candidate: a CryptoPkg-derived SMM driver further down the stack, or
possibly a Lenovo-specific shim atop an Intel TXE/ME service.

## Strings: zero

`strings -el` returned nothing. `strings -a` returns only register-context fragments.
This module is pure binary code with no human-readable text — typical for SMM math/dispatch
modules.

## Crypto signature scan: zero hits

None of the standard crypto constant tables match:
- SHA-256 K[]: no
- MD5 init constants: no
- SHA-1 init constants: no
- AES S-box: no
- CRC32 table: no
- Tiger init: no

That's because **the actual hash isn't here**. The constants will be in the underlying
HashService implementation, wherever that lives.

## Architecture: who does what

```
┌──────────────────────────────────────────────────────────────────┐
│ LenovoCryptServiceSmm.efi (THIS MODULE — 3.9 KB)                 │
│                                                                  │
│ Produces:                                                        │
│   Stage-1 hash protocol  E3ABB023-...                            │
│   Stage-2 hash protocol  E01FC710-...                            │
│                                                                  │
│ Both implementations are WRAPPERS around a generic hash service  │
└──────────────────────────────────────────────────────────────────┘
                               │
                               │ calls into Lenovo HashService:
                               │   slot 0x00: CreateContext(algoGuid)
                               │   slot 0x10: ReleaseContext
                               │   slot 0x18: Update(data, len)
                               │   slot 0x20: Final(out)
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ Some other module — UNIDENTIFIED                                 │
│                                                                  │
│ Implementer of:                                                  │
│   Lenovo HashService (6C48F74A-...)                              │
│     accessed via dispatcher protocol 69188A5F-...                │
│                                                                  │
│ Likely candidates:                                               │
│   - LenovoCryptService.efi (the DXE peer of THIS module)         │
│   - Some PEI/early DXE crypto core                               │
│   - A vendor-specific shim atop Intel ME crypto                  │
└──────────────────────────────────────────────────────────────────┘
```

This is a layered design. CryptServiceSmm is a *façade* — it publishes the named
protocols that PasswordCp and other modules depend on, but does the work via a
lower-level service. The hash algorithm itself is opaque from this module's perspective.

## entry() walkthrough

The entry point is at file offset `0x838`. It does the following:

1. **Calls FUN_00000B9C (init helper)** to look up several base protocols and stash them.
   The helper locates:
   - `1390954D-DA95-4227-9328-7282C217DAA8` (Lenovo proprietary, seen in PasswordCp data)
   - `6AFD2B77-98C1-4ACD-A6F9-8A9439DE0FB1` (Lenovo proprietary, seen in PasswordCp data)
   - `4C8A2451-C207-405B-9694-99EA13251341` (Lenovo proprietary, seen in PasswordCp data)
   - **`5B1B31A1-9562-11D2-8E3F-00A0C969723B`** = standard EFI Loaded Image Protocol
   - `BC62157E-3E33-4FEC-9920-2D3B36D750DF` (Lenovo proprietary)

   That last group of three (`1390954D`, `6AFD2B77`, `4C8A2451`) tells us this module
   shares a foundation with the password subsystem — they're SMM service GUIDs commonly
   pulled in across the credential-handling stack.

2. **RegisterProtocolNotify** on `FE2965BB-5A8E-43B3-AEDD-ABCC63003D14` (the same Lenovo
   proprietary GUID used in PasswordCp at 0x2F0). The notify callback is the function
   table at `.text` offset `0x240`. This means: don't activate hash services until the
   FE2965BB-... protocol is published by some other module. That's a load-order constraint.

3. **LocateProtocol(`69188A5F-6BBD-46C7-9C16-55F194BEFCDF`)** → stored in `DAT_00000E70`.

   This is the *dispatcher* through which the actual hash service is reached. It's a
   protocol with a 4-method table at offsets +0x00, +0x10, +0x18, +0x20 — exactly what a
   create/release/update/final hash interface looks like.

4. **LocateProtocol(`9F5E8C5E-0373-4A08-8DB5-1F913316C5E4`)** → stored in `DAT_00000DC0`.

   This is the SMI handler registration protocol. We already saw it consumed by
   `LenovoSvpManagerSmm.efi` (at offset 0x4B0 in that module). It's the system bus by
   which DXE-side code reaches SMM-side handlers via SMI commands.

5. **Three handler registrations** through the SMI registration protocol:
   - Command `0x83` → `FUN_00000560` (this is the **stage-1 hash service handler**)
   - Command `0x8F` → `FUN_000006A8` (this is the **stage-2 hash service handler**)
   - Command `0x90` → `LAB_00000800` (a different operation — see below)

6. **FUN_00000A80** — initializes a CMOS scratchpad area at `DAT_00000E68` by reading
   8 bytes from CMOS offsets 0xB0..0xB7 (using the I/O port pair 0x70/0x71 — standard CMOS)
   and storing them in a global. There's also a second, parallel function `FUN_00000B10`
   that *writes* 8 bytes back to the same CMOS region; it's not called from entry but is
   reachable from an SMI handler. So this module also reads/writes 8 bytes of CMOS state
   for some unidentified purpose. Likely a transient nonce or a session token used to
   tag hash operations between SMM transitions.

The fact that CMOS bytes 0xB0..0xB7 appear with reads via I/O 0x70/0x71 and writes via
I/O 0x72/0x73 (extended CMOS) is a consistent pattern. CMOS bytes 0xB0–0xB7 are
typically OEM-reserved.

## The two hash handlers — FUN_00000560 and FUN_000006A8

Both are nearly structurally identical. Each:

1. Validates the SMM communication buffer (returns error if a length field at +0x10 is
   too small, < 8 bytes).
2. Loops over input data in 4-byte chunks calling `FUN_00000930` (the dispatcher into
   the underlying hash service) — this is the **Update** phase.
3. After the input loop, calls `FUN_00000930` once more with a different size — the
   **Final** phase.
4. Calls `protocol_dc0->slot+0x10` to mark the SMI handler complete.

`FUN_00000930` is the dispatcher. It does:

```
  protocol_e70->slot0(self, &GUID@0x3e0, &ctx)         ; CreateContext for "this hash"
  protocol_e70->slot18(ctx, RBX/RDI args, R9)          ; Update with data
  protocol_e70->slot20(ctx, output_ptr, 3, &local_18)  ; Final, sized 3 (probably mode)
  protocol_e70->slot10(ctx)                            ; ReleaseContext
```

The GUID at `0x3E0` is `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE`. That's the
**algorithm-identification GUID** passed to the underlying hash service. It identifies
*which* algorithm the underlying service should use — analogous to how
`EFI_HASH_ALGORITHM_SHA256_GUID` identifies SHA-256 for the standard EFI Hash protocol.

This GUID is not a published standard EFI hash algorithm GUID. Its meaning is internal
to the Lenovo HashService — it is "the algorithm Lenovo uses for this kind of hash."

The implication: this module asks the underlying service to compute a Lenovo-specific
hash by passing this GUID, and the underlying service has a table mapping that GUID to
some primitive (likely simple — XOR/ADD/ROL or a stripped-down standard hash, given
that no recognizable constants live anywhere in either module's data).

## Why two handlers (0x83 and 0x8F) for "the same hash"

`FUN_00000560` and `FUN_000006A8` both call into the dispatcher, but with *slightly*
different argument layouts. My read: they implement the two stages (stage-1 and stage-2)
of the password pipeline we traced via the protocol GUIDs.

The natural binding:
- SMI command **0x83** → stage-1 hash protocol (`E3ABB023-...`) implementer
- SMI command **0x8F** → stage-2 hash protocol (`E01FC710-...`) implementer

Both stages call into the same underlying hash primitive (same GUID `6C48F74A-...`).
The two stages may differ in input handling (length, salt, prefix bytes) rather than in
the base hash algorithm. That would match the typical "hash twice with different
salts" or "iterate hash N times" construction.

## The third handler — `LAB_00000800` (command 0x90)

This is a much simpler handler. It:
- Reads three small scalars from the SMM buffer at offsets `+0x14`, `+0x08`, `+0x10`
- Calls `FUN_00000930` with those values
- Calls `FUN_00000B84` (memzero) on a 0x19-byte region
- Calls `FUN_000009E4`

`FUN_000009E4` does some interesting work:
- Allocates two stack buffers (0x11 and 0x20 bytes), memzeros both
- Copies 7 bytes from the input into the first buffer, then 10 bytes from the CMOS
  scratchpad (`DAT_00000E18`) into the same buffer
- Calls `FUN_00000930` with the 0x11-byte buffer as input and the 0x20-byte buffer as
  output
- Copies the 0x20-byte output back to the caller's destination

So command `0x90` looks like:
**"compute a hash over (7 bytes of caller input concatenated with 10 bytes of CMOS
scratchpad), produce a 32-byte digest, return it."**

That's a *keyed* hash — the 10 bytes of CMOS function as a per-machine key. This is
exactly the "key from EC/CMOS at runtime" pattern I predicted from the absence of
crypto constants. It's also a very plausible construction for binding a value to the
machine's identity (asset, lockbox, license).

The 32-byte output size is interesting — it's the natural size for SHA-256, which is
a hint that the underlying primitive may indeed be something like SHA-256 (just with
keyed input rather than vanilla). The constants would be in whatever module produces
the `6C48F74A-...` algorithm GUID.

## Clean function map

```
LenovoCryptServiceSmm.efi
├── entry(ImageHandle, SmmSystemTable)
│   ├── FUN_00000B9C — init: locate prerequisite protocols
│   ├── RegisterProtocolNotify(FE2965BB-...) ← gating event
│   ├── LocateProtocol(69188A5F-...) → DAT_E70 (hash dispatcher)
│   ├── LocateProtocol(9F5E8C5E-...) → DAT_DC0 (SMI handler registry)
│   ├── reg_handler(0x83, FUN_00000560)   ← stage-1 hash entry
│   ├── reg_handler(0x8F, FUN_000006A8)   ← stage-2 hash entry
│   ├── reg_handler(0x90, FUN_00000800)   ← keyed hash with CMOS data
│   └── FUN_00000A80 — read CMOS B0..B7 into DAT_E68 (8-byte session state)
│
├── FUN_00000560 — SMI 0x83 handler (stage-1 hash entry)
│   └── multiple calls to FUN_00000930 in 4- and 8-byte input chunks
│
├── FUN_000006A8 — SMI 0x8F handler (stage-2 hash entry)
│   └── same shape as 0x83 with slightly different argument layout
│
├── LAB_00000800 — SMI 0x90 handler (keyed hash over (input || CMOS state))
│   └── FUN_000009E4 builds the (7 + 10)-byte input and runs the hash
│
├── FUN_00000930 — the hash dispatcher
│   ├── protocol_E70->Create(self, GUID 6C48F74A-..., &ctx)
│   ├── protocol_E70->Update(ctx, data, len)
│   ├── protocol_E70->Final(ctx, output, mode=3, ...)
│   └── protocol_E70->Release(ctx)
│
├── FUN_000009C8 — small init: zero the 10-byte CMOS scratchpad mirror
├── FUN_000009E4 — keyed-hash composer for command 0x90
├── FUN_00000A68 — small SMI variant; calls into FUN_00000930
├── FUN_00000A80 — initialize CMOS scratchpad (read CMOS B0..B7)
├── FUN_00000B10 — write CMOS scratchpad back (write CMOS B0..B7)
│
└── helpers:
    FUN_00000B9C — initialization (locate prerequisite protocols)
    FUN_00000B40 — memcpy
    FUN_00000B84 — memset wrapper
    FUN_00000CF4 — CMOS read (I/O port 0x70/0x71 + extended 0x72/0x73)
    FUN_00000D14 — CMOS write
    FUN_00000D40 — memset core
```

## What this means for the password pipeline

Updated map:

```
PasswordCp typed-buffer
   ↓
   ↓ stage-1 hash protocol (E3ABB023-...) — produced by THIS module
   ↓     -> SMI 0x83 -> FUN_00000560 -> dispatch to Lenovo HashService
   ↓     -> Lenovo HashService computes hash (algorithm = 6C48F74A-...)
   ↓     -> 16-byte digest (likely; PasswordCp uses 16-byte buffers)
   ↓
   ↓ stage-2 hash protocol (E01FC710-...) — produced by THIS module
   ↓     -> SMI 0x8F -> FUN_000006A8 -> dispatch to Lenovo HashService
   ↓     -> 16-byte final digest
   ↓
LenovoSvpManagerDxe -> SMI bridge -> LenovoSvpManagerSmm
   ↓
   ↓ Lenovo EC Mailbox protocol
   ↓
EC EEPROM
```

The ALGORITHM is still hidden one level below — in whichever module *implements* the
`69188A5F-...` dispatcher and the `6C48F74A-...` algorithm. Almost certainly that's
**`LenovoCryptService.efi`** (the non-SMM peer of this module), which is on the
SVP-storage consumer list and is named appropriately.

## What remains unanswered

1. **What primitive does `6C48F74A-...` map to?** SHA-256? A Lenovo XOR/ROL chain? Something
   else? We need to extract `LenovoCryptService.efi` (the DXE peer) — the algorithm
   GUID is dispatched by that module.

2. **What is the role of the 8 bytes of CMOS at offsets B0..B7?** They're read at init,
   never used by the password handlers (0x83/0x8F), but mixed into command 0x90's hash.
   Probably a session/asset token.

3. **What is command 0x90 actually for?** "Hash X concatenated with CMOS state" is a
   primitive that could authenticate session-bound payloads. Worth tracking who calls
   SMI 0x90.

## Architectural takeaway

We discovered the system has a **clean three-tier crypto design**:

1. **Caller-facing protocols** (stage-1 / stage-2 hash) — what the password pipeline thinks
   it's calling. Produced by THIS module.
2. **Generic hash dispatcher** — `69188A5F-...` — a multi-algorithm interface taking an
   algorithm GUID. Located but not implemented here.
3. **Algorithm implementations** — keyed by their GUID (e.g. `6C48F74A-...`). Implemented
   in some other module, likely `LenovoCryptService.efi`.

That's a sensible OEM design from 2012 — the same pattern OpenSSL uses for ENGINE
plugins. The actual hash math is one module further out, and that's the next target.

## Suggested next step

Extract `LenovoCryptService.efi` (the DXE peer; this module's name without the "Smm"
suffix). It's almost certainly the producer of the `69188A5F-...` dispatcher and the
implementer of the `6C48F74A-...` algorithm. That's where the actual byte-mixing math
lives — the byte loops, the constants (if any), the round structure.

That module will close the loop. We'll know exactly what algorithm hashes the password.

## Disclaimer

As before: this is structural mapping, not vulnerability research. None of these findings
constitute a bypass path. The point is to understand what the firmware does on this
machine I own — nothing more.
