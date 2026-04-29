# T430u Crypto Service (DXE side) Module Analysis

## Module
- **File**: `LenovoCryptService.efi`
- **Size**: 19,552 bytes
- **Type**: PE32+ x86-64, EFI boot service driver (DXE)
- **Role**: Implements `EFI_HASH2`-style hash dispatcher protocol AND a full software AES-CBC engine. Acts as the *implementer* layer for the password-handling subsystem.

## Headline finding

**The module contains a textbook software AES implementation.** Specifically:
- Four forward T-tables at `0x510`, `0x910`, `0xD10`, `0x1110` (1 KB each)
- Four inverse T-tables at `0x1510`, `0x1910`, `0x1D10`, `0x2110`
- Inverse S-box at `0x2510`
- Encrypt routine at `FUN_00004684`, decrypt at `FUN_000047a8`, dispatcher at `FUN_0000323c`
- Operates in **CBC mode** (XOR-with-previous-block before each round)
- Supports variable round counts (10/12/14 rounds → AES-128/192/256)

This is the canonical Daemen & Rijmen reference implementation pattern — same shape used in OpenSSL, libgcrypt, EDK2's `CryptoPkg`, and most other libraries. Not a custom Lenovo algorithm.

## The hash protocols ARE just hash protocols

Confirmation: `D0B3D668-...` (the protocol consumed first by `FUN_00002994`) is invoked with a state-machine pattern (op_type 3 → "Update", op_type 4 → "Update with key"-like, op_type 2 → "Final"). It's used as a generic hash service. The thing being asked of it through the algorithm GUID `6C48F74A-...` is what produces the digest.

What I previously labeled "hash" protocols at the SMM peer (`E3ABB023-...` and `E01FC710-...`) are now best understood as: **two named entry points that produce a 16-byte digest from a typed password** by using AES as the underlying primitive.

The DXE peer publishes both protocols (their GUIDs are at offsets `0x470` and `0x450` in this module's data).

## What the AES is for

Three distinct uses of AES are visible in this module's call graph:

1. **Password hash construction.** When stage-1 or stage-2 protocol is invoked, the module ultimately produces a 16-byte digest. The AES primitive operates either:
   - As a Davies-Meyer-style one-way function (`H = AES_pwd(IV) XOR IV`), where the password becomes the AES key and the output is taken as the digest, OR
   - As CBC-MAC where the password is the plaintext stream and a fixed IV+key produce a 16-byte tag, OR
   - In some other AES-based hash construction.
   - We have not yet definitively identified which by reading the call graph all the way through, but all of these naturally produce 16-byte output.

2. **Encrypted EC EEPROM payloads.** The presence of full encrypt+decrypt and CBC tail-handling (which only matters if you're processing variable-length data, not just a single block of password material) suggests this AES is also used for general-purpose decryption of payloads from EC storage.

3. **`LenovoScratchData` and `LenovoSecurityConfig` variable encryption.** Same logic: both EFI variables (named in the SMM peers) hold security state, and their contents are likely AES-encrypted at rest with a per-machine or fixed key.

## Verified GUIDs in this module's data section

| Offset | GUID | Role |
|---|---|---|
| `0x260` | `D0B3D668-16CF-4FEB-95F5-1CA3693CFE56` | Lenovo proprietary — looks like a hash-protocol handle |
| `0x2B0` | `69188A5F-6BBD-46C7-9C16-55F194BEFCDF` | Hash dispatcher (also used by SMM peer) |
| `0x300` | `C5A3095A-87F7-4AF8-B393-09CC4AF08739` | Lenovo proprietary (unknown function) |
| `0x310` | `C0206BF0-6D0A-4988-B7E0-BF2FEB6D747D` | Lenovo proprietary (unknown function) |
| `0x330` | `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE` | Hash algorithm identifier (Lenovo-specific) |
| `0x450` | `E01FC710-BA41-493B-A919-53583368F6D9` | Stage-2 password-hash protocol — **published here** |
| `0x470` | `E3ABB023-B8B1-4696-98E1-8EEDC3D3C63D` | Stage-1 password-hash protocol — **published here** |
| `0x4D0` | `82B244DC-8503-454B-A96A-D0D2E00BF86A` | SVP storage protocol (consumer reference) |
| `0x4F8` | (additional GUID at this offset, used by `FUN_00002838`) |

## AES T-table layout (verified)

| Address | Table | Confirmed |
|---|---|---|
| `0x510` | Te0 (forward T-table 0) | T0[0] = `a5 63 63 c6` matches Rijndael spec |
| `0x910` | Te1 (forward T-table 1) | XREF'd by encrypt round at 0x3b88 etc. |
| `0xD10` | Te2 (forward T-table 2) | XREF'd by encrypt round |
| `0x1110` | Te3 (forward T-table 3) | XREF'd by encrypt round |
| `0x1510` | Td0 (inverse T-table 0) | XREF'd by decrypt round at 0x4199 etc. |
| `0x1910` | Td1 | XREF'd by decrypt round |
| `0x1D10` | Td2 | XREF'd by decrypt round |
| `0x2110` | Td3 | XREF'd by decrypt round |
| `0x2510` | Inverse S-box | Used in final decrypt round (no MixColumns) |

The forward S-box does NOT appear as a standalone table — that's expected for a T-table-only implementation. T-tables encode the forward S-box implicitly (`Te0[i] = SBOX[i] * 02 || SBOX[i] || SBOX[i] || SBOX[i] * 03` per the Rijndael paper).

## Function map

```
LenovoCryptService.efi
│
├── entry (.text:0x2638) — minimal loader
│   ├── FUN_00003140 (.text:0x3140) — preliminary init
│   ├── FUN_0000289c — install something (no detailed trace yet)
│   ├── BS->LocateProtocol(GUID@0x410, ...)
│   └── BS->RegisterProtocolNotify(LAB_0000288c, ...) at offset 8
│
├── FUN_00002690 — CMOS-related routine
│   └── reads 7 bytes from CMOS via FUN_000031f0, accumulates a checksum,
│       reads CMOS B7, compares; if mismatch, writes via FUN_00003210
│       (this is a CMOS data-block integrity check)
│
├── FUN_0000273c — initialize CMOS write region (writes 8 zero bytes)
│
├── FUN_00002760 — SVP-storage-aware operation (called via callback table @ 0x240)
│   ├── BS->LocateProtocol(GUID@0x4D0 = SVP storage protocol)
│   ├── reads 8 bytes from EC via 0x57 sub-command (same EC protocol pattern as SvpManagerSmm)
│   ├── XORs each byte with a CMOS-derived value (FUN_000031f0)
│   ├── CALL FUN_00002994 with size=8 — runs hash on the XORed buffer
│   └── BS->something at +0x160 — writes result somewhere
│
├── FUN_00002838 — SVP-storage tool (called via callback)
│   └── reads SVP block, returns specific byte
│
├── FUN_00002994 ★★★ THE HASH PROTOCOL CALLER
│   ├── BS->LocateProtocol(GUID@0x260) → protocol handle (the actual hash service)
│   ├── BS->LocateProtocol(GUID@0x2B0 = 69188A5F dispatcher) → secondary handle
│   ├── FUN_000028c4 — context allocation (returns ptr)
│   ├── State-machine sequence:
│   │   Setup: ctx[0x18] = 0; ctx[0x10] = 0x28; ctx[0x28] = dispatcher
│   │           ctx[0x30] = &GUID@0x330 (algorithm 6C48F74A)
│   │           proto[0x260]->func0(ctx) → hash session start
│   │   Step 2:  ctx[0x18] = 3; ctx[0x10] = 0x30 → hash Update
│   │   Step 3:  ctx[0x18] = 4; ctx[0x10] = 0x38 → hash Update (with key/extension)
│   │   Step 4:  ctx[0x18] = 2; ctx[0x10] = 0x20 → hash Final
│   ├── BS->CopyMem (or similar) → write 0x20-byte digest to caller
│   └── BS->FreePool ctx
│
├── FUN_00003008 — second hash entry, similar shape to FUN_00002994
│   └── different GUID at 0x300/0x310 — likely used for different consumers
│
├── FUN_00003140 (preliminary init)
├── FUN_00003160 — internal helper
├── FUN_000031f0 — CMOS read (I/O 0x70/0x71 + extended 0x72/0x73)
├── FUN_00003210 — CMOS write (same I/O pattern with output value)
│
├── FUN_0000323c ★★★ AES MODE DISPATCHER
│   if (param_6 != 0):  // encrypt flag
│     stack[0x28] = LAB_00003ab0  // encrypt round body
│     CALL FUN_00004684  // encrypt CBC loop
│   else:
│     stack[0x28] = LAB_000040a0  // decrypt round body
│     CALL FUN_000047a8  // decrypt CBC loop
│
├── LAB_00003ab0 ★★★ AES SINGLE-BLOCK ENCRYPT
│   ├── Initial AddRoundKey: XOR the 16-byte block with first round key
│   ├── Read round count from key_schedule[0xF0], halve, store in R15
│   ├── Main rounds: each round does
│   │     state[0..3] = Te0[s0_byte0] ^ Te1[s1_byte1] ^ Te2[s2_byte2] ^ Te3[s3_byte3] ^ rk
│   │     (verified in disassembly at 0x3b88, 0x3b9a, 0x3ba6, 0x3bb2)
│   └── Final round (no MixColumns): S-box lookup + ShiftRows + AddRoundKey
│
├── LAB_000040a0 — AES SINGLE-BLOCK DECRYPT (uses Td0..Td3, then InvSBox at 0x2510)
│
├── FUN_00004684 ★★★ AES-CBC ENCRYPT (multi-block)
│   ├── R13 = 0x10 (block size)
│   ├── For each 16-byte block:
│   │     XOR plaintext with previous ciphertext (or IV for block 0)
│   │     CALL [single_block_function_pointer]   ; LAB_00003ab0
│   ├── Tail handling for partial blocks (final byte-by-byte XOR)
│   └── JMP FUN_000049c0 (memcpy to copy result)
│
├── FUN_000047a8 — AES-CBC DECRYPT (multi-block, mirror of encrypt)
│
└── FUN_000049c0 — simple memcpy
```

## Notes on the encrypt round (verified disassembly excerpt)

```
;;; LAB_00003ab0:  AES single-block encrypt  (4-T-table inner loop)
;;;
;;; Line 0x3ad5: load plaintext bytes into 4 32-bit columns
;;; Lines 0x3ae2-0x3b6c: pack bytes into uint32 words
;;; Line 0x3b14: XOR R10D with first 4 bytes of round key (initial AddRoundKey)
;;; Lines 0x3b34, 0x3b50, 0x3b70: same for other 3 columns
;;;
;;; Line 0x3c1a: MOV R15D, [RDI + 0xf0]   ; load round count from key sched
;;; Line 0x3c3b: SAR R15D, 0x1            ; halve to get loop count
;;;
;;; LAB_00003c9d: ROUND BODY (repeats R15 times)
;;; Lines 0x3cc1, 0x3cd2, 0x3cdd: 4 T-table lookups + XORs into one column
;;; ... same for the 3 other columns ...
;;; Line 0x3eb2: SUB R15D, 0x1; JNZ
```

That is **bit-exact textbook T-table AES**. Same pattern as OpenSSL's `AES_encrypt`, EDK2's `AesEncryptInternal`, and any reference Rijndael implementation.

## What remains uncertain (to be honest about)

1. **The exact AES construction used for password hashing.** I see all the pieces — AES, an SVP storage read, a hash-service dispatcher — but haven't traced through the exact composition. It could be any of several keyed-hash-from-cipher constructions.

2. **The role of GUID `6C48F74A-...`.** I called it the "hash algorithm GUID" because that's what its position in the call sequence suggests. But there's no string evidence; the meaning is structural.

3. **The role of GUIDs at `0x300`, `0x310`.** Used by `FUN_00003008` (a second hash entry point), but not yet traced.

4. **The exact key source.** AES needs a key. Where does it come from? Three plausible sources we've seen mentioned in the larger architecture:
   - The 16 bytes of EC EEPROM data we know contain SVP material (read via 0x57 sub-command)
   - The 8 bytes of CMOS at `0xB0..0xB7` we found in the SMM peer
   - A constant embedded in the module (we haven't found it as a 16-byte signature, though)
   - Some combination

## Architectural takeaway, revised

Updated map of the password subsystem:

```
PasswordCp typed buffer (≤64 bytes, restricted charset)
    │
    │ via stage-1 hash protocol (E3ABB023-...) — published by THIS module
    │ via stage-2 hash protocol (E01FC710-...) — also published by THIS module
    ▼
LenovoCryptService.efi (this module)
    ├── builds an AES-based hash construction
    ├── uses the AES engine in this same module (T-table software)
    └── may also coordinate with the SMM peer (LenovoCryptServiceSmm.efi) for SMI handlers
    │
    ▼
LenovoSvpManagerDxe.efi (compares result to stored value)
    │ via SMI bridge
    ▼
LenovoSvpManagerSmm.efi (SVP cache, lockout, EC mailbox)
    │ via Lenovo EC Mailbox protocol (0DE8BACF-...)
    ▼
LenovoMailBoxSmm.efi (the EC bridge, not yet analyzed)
    │
    ▼
EC EEPROM (the actual stored credential material)
```

## What's interesting about this design

Several things, now that we have the picture:

1. **They used real AES, not a custom hash.** This is *good* engineering. AES has been studied to death; rolling your own would have been worse.

2. **Hardware acceleration was available but not used.** Ivy Bridge has AES-NI. This implementation is pure software T-table — meaning it's also designed to run pre-microcode-load (early boot) or in environments where AES-NI is disabled (some SMM contexts).

3. **The two-stage construction.** Why hash twice? Most likely because:
   - Stage 1 transforms the password from "raw user input" to a "machine-bound preliminary digest"
   - Stage 2 mixes in additional state (perhaps the EC's per-machine secret) to produce the final digest stored on disk
   - This makes the stored digest dependent on both the password AND the machine, so a stolen EC EEPROM dump can't be brute-forced offline using just dictionary words

4. **The SMM/DXE split.** DXE handles protocol publication and the AES math. SMM handles SMI-driven dispatch, lockout enforcement, and EC mailbox brokerage. This is a sensible defense-in-depth design: even if a DXE-resident attacker compromised CryptService, they couldn't directly modify the SVP state without going through SMM.

## What I'd verify next (genuinely-uncertain items)

1. **Trace `FUN_00002994` to find where the AES key actually originates.** This is the missing link to fully name the construction.

2. **Look at `FUN_00003008` — the second hash entry point** with GUIDs at `0x300/0x310`. It might be a different AES use case entirely (maybe variable encryption, maybe a separate digest service).

3. **Pull `LenovoMailBoxSmm.efi`** to verify the EC mailbox protocol producer (still not directly confirmed).

## Disclaimer

This is structural reverse-engineering for personal comprehension of hardware I own. Nothing in this analysis constitutes a bypass path. Knowing the password is hashed with AES does not let you recover or modify the password — the security of the construction relies on the hash being one-way (which AES-based MAC-style constructions are, given a secret key) and the per-machine key being inaccessible without SMM privilege.

## Correction to earlier writeups

In the `cryptservice_smm_analysis.md` writeup I claimed the SMM peer was "the producer of both stage-1 and stage-2 hash protocols." That was wrong, or at least incomplete. **The DXE peer (this module) embeds both protocol GUIDs at `0x470` and `0x450`, which means it is also a producer.** The most likely architecture is:
- DXE peer publishes the protocol structures with function pointers
- The function pointers route through SMI to the SMM peer's registered handlers (`0x83`, `0x8F`)
- The SMM peer then calls into the AES engine *here* via shared state

We have a producer/consumer ambiguity in the current data. Resolving it requires tracing exactly when each module's `InstallProtocolInterface` runs at boot. That's a thread for the next session.
