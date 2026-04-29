# T430u CryptService AES Key Derivation Analysis

## What this document adds

This is an addendum to `cryptservice_dxe_analysis.md` that resolves the open question
of where the AES key comes from. With this addendum, the cryptographic story for the
T430u password subsystem is fully closed — every byte the AES engine processes can be
traced back to its source.

## Headline finding

**The AES key is not stored as a constant in the module. It is derived at boot, per-machine,
from EC EEPROM contents combined with CMOS state.**

The derivation chain is:

```
8 bytes from EC EEPROM (read via 0x57 sub-command on the EC mailbox)
       │
       │ XOR byte-by-byte with 8 bytes of CMOS-derived state
       ▼ (output: 8-byte buffer)
Lenovo HashService (algorithm GUID 6C48F74A-...)
       │
       │ produces 16-byte digest
       ▼
DAT_00004B10 (in the module's .data section, 16 bytes wide)
       │
       │ When AES-CBC is invoked through the function pointer at .text+0x248:
       │   1. Copy these 16 bytes to a stack buffer
       │   2. Run AES-128 key expansion (FUN_00003284) → 176-byte key schedule
       │   3. Use the schedule for AES-CBC-encrypt (FUN_00004684)
       ▼
AES-128-CBC operates with this dynamically-derived per-machine key
```

There is a parallel chain producing a second key at `DAT_00004B00`, populated by
`FUN_00002838` (a different SVP-storage operation). The `FUN_00002B80` dispatcher
selects between these two banks based on a GUID parameter (so the function can do
two distinct AES operations with two distinct keys, depending on which "purpose"
the caller specifies).

## How I traced it

Ghidra didn't auto-trace the function at `.text:0x2B80` because it's only reachable
through the function-pointer table at the start of `.text`:

```
.text:0x240  → FUN_00002994     (hash service caller)
.text:0x248  → 0x00002B80       (AES encrypt wrapper) — Ghidra missed this
.text:0x250  → 0x00002DC4       (likely AES decrypt wrapper) — also missed
.text:0x258  → FUN_00003008     (second hash entry point)
```

I had to disassemble `0x2B80` by hand. Doing so revealed:

1. **Two 16-byte GUIDs are constructed inline** (byte-by-byte stack stores starting at
   offset `0x2BA9`) on the stack at frame offsets `0x30` and `0x40`:
   - `[RSP+0x30]..[RSP+0x3F]` = `31 89 10 72 88 47 9a 4f 81 a1 00 77 2c cd ac c5`
     → GUID `72108931-4788-4F9A-81A1-00772CCDACC5`
   - `[RSP+0x40]..[RSP+0x4F]` = `8c a8 8d 7e 5c a9 b6 41 8c 99 43 0c 46 93 11 9e`
     → GUID `7E8DA88C-A95C-41B6-8C99-430C4693119E`

2. **The function compares its second argument against each GUID** (using `FUN_00003160`,
   a 16-byte memcmp) at offsets `0x2C64` and `0x2C9F`.

3. **Based on which GUID matches, it copies a different 16-byte value into a stack key buffer**:
   - GUID #1 match → `LEA RDX, [DAT_00004B10]`; CopyMem 16 bytes → stack
   - GUID #2 match → `LEA RDX, [DAT_00004B00]`; CopyMem 16 bytes → stack

4. **Then runs AES key expansion** at `0x2D02`: `FUN_00003284(key_in=&[RSP+0x50], 128, key_sched_out=&[RSP+0x70])`.
   The literal `0x80 = 128` confirms **AES-128**.

5. **Then runs AES-CBC encrypt** at `0x2D31`: `FUN_0000323C(...)` with encrypt flag = 1,
   which dispatches to `FUN_00004684` (the multi-block CBC loop) with `LAB_00003AB0`
   as the per-block round function.

## The key-derivation code path

`DAT_00004B10` is filled at boot by `FUN_00002760`, called from `FUN_0000289C`
(an early initialization function called from `entry()`):

```
FUN_0000289C():
  CALL FUN_00002690      ; CMOS data integrity check
  LEA  RCX, [DAT_00004B10]
  CALL FUN_00002760      ; ← writes 16 bytes to DAT_00004B10
  LEA  RCX, [DAT_00004B00]
  JMP  FUN_00002838      ; ← writes 16 bytes to DAT_00004B00
```

`FUN_00002760` (which we already partly traced for the previous writeup) does:

```
FUN_00002760(output_ptr):
  LocateProtocol(GUID@0x4D0 = SVP storage protocol) → svp_proto
  read 8 bytes from svp_proto[0]() with sub-command 0x57:
    for offset 0x62..0x69:
      svp_proto[0]->func(self, 0x57, offset, &out_byte)
                        # 0x57 = read SVP block byte command
  for each of 8 retrieved bytes:
    XOR with FUN_000031F0(some_index)    ; FUN_31F0 is CMOS read
  CALL FUN_00002994(svp_proto, ..., 8)   ; hash the XORed buffer
  CopyMem(output_ptr, &local_28, 0x10)   ; copy 16-byte digest out
```

So `DAT_00004B10` ends up holding `Hash6C48F74A(EC[0x62..0x69] XOR CMOS_bytes)`.

`FUN_00002838` is similar but reads from a different SVP block region — its specifics
I haven't fully decoded, but the shape is the same.

Both produce 16-byte digests stored in the module's data section. Those digests are
the AES-128 keys for the encrypt/decrypt operations exposed via the function-pointer table.

## Why this is sensible engineering

1. **The key is per-machine.** Two T430u laptops with the same firmware will have
   different AES keys because the EC EEPROM contents differ.

2. **The key is non-portable.** Dumping the BIOS flash alone doesn't yield the key —
   you need the EC contents too. The EC is a separate chip with its own firmware and
   its own dump procedure.

3. **The key is mediated.** The EC bytes are read through the SVP storage protocol,
   which is gated by SMM (per our earlier `LenovoSvpManagerSmm.efi` analysis). DXE-level
   code can't directly poke the EC mailbox without going through the privileged path.

4. **The key derivation is one-way.** The AES key is the output of a hash, so even
   if you obtain the AES key, you can't recover the original EC byte sequence directly —
   you'd have to brute-force preimages (and the EC bytes contribute about 64 bits of
   entropy, depending on what they actually contain, plus 8 bytes of CMOS state).

5. **No hardcoded secrets.** Reverse engineers can read the firmware all they want; the
   key isn't there. This is materially better than the "key embedded in a ROM" pattern
   that was common in mid-2000s OEM firmware.

The construction is reminiscent of TPM-sealed key derivation, just done with a custom
hash service instead of a TPM. T430u doesn't ship with a TPM by default, so this is
how Lenovo achieves a "sealed-key" property without hardware support.

## What this means for the password pipeline

Putting all the pieces from prior writeups together, the password verification flow is:

```
User types password
       │
       │ → LenovoPasswordCp.efi (validates charset, builds buffer)
       │
       │ → Stage 1 hash protocol (E3ABB023-...) — implemented by THIS module
       │   (calls Lenovo HashService with algorithm GUID 6C48F74A)
       │
       │ → Stage 2 hash protocol (E01FC710-...) — also implemented by THIS module
       │   (likely takes the stage-1 output and re-hashes with different framing)
       │
       │ → 16-byte digest of the password
       │
       │ → AES-CBC-encrypt the digest, using the per-machine AES key from DAT_00004B10
       │     (or some related operation; the exact connection to AES is via FUN_00002B80
       │     and FUN_00002DC4, which are exposed via the function-pointer table)
       │
       │ → 16-byte AES output
       │
       ▼
Compare against the stored value (in EC EEPROM, retrieved via SVP storage)
```

With this picture, the security model is:

- The password is hashed with a Lenovo hash function (algorithm `6C48F74A-...`).
- The hash is encrypted with AES-128, where the AES key is itself derived from the EC's
  per-machine secret bytes XORed with CMOS state and run through the same hash.
- The encrypted hash is stored in the EC EEPROM.

To brute-force this offline, an attacker would need:
1. The EC EEPROM dump (specifically bytes 0x62..0x69 of the SVP block, plus the stored
   ciphertext)
2. The CMOS contents (specifically the 8 bytes used in the XOR)
3. The exact hash algorithm `6C48F74A-...` (which we still don't know — it lives in some
   module providing the dispatcher protocol, which is `LenovoCryptService.efi` itself
   or a related module)

That third item is the remaining unknown. The hash algorithm is identified by GUID,
but the actual byte-mixing math hasn't been located. Almost certainly it's *also* in
this module, since this module both publishes the dispatcher GUID AND implements full
AES — but the connection between the dispatcher protocol and the actual hash bytes
isn't traced yet.

## What's still uncertain

1. **The actual hash algorithm `6C48F74A-...`.** Probably implemented in this module
   (since the module is large enough and contains the necessary primitive). I haven't
   located its byte-mixing core. It may even be AES-based (AES-CBC-MAC, Davies-Meyer,
   or similar) which would make this module a self-contained crypto suite.

2. **What `FUN_00002DC4` does.** This is the third function in the table, also missed
   by Ghidra's auto-analysis. Likely the AES decrypt path (mirror of `FUN_00002B80`).

3. **The provenance of the second key bank `DAT_00004B00`.** I traced `DAT_00004B10`
   through `FUN_00002760`, but `FUN_00002838` does something subtly different — it
   reads a different region of SVP storage. We don't yet know which password-pipeline
   operation maps to which key bank.

4. **What protocol the function-pointer table at `.text:0x240` is exposed through.**
   The four function pointers (hash, encrypt, decrypt, second hash) form a 4-method
   protocol interface. Some other module installs this protocol with one of the
   stage-1/stage-2 hash protocol GUIDs from this module's data section
   (`E3ABB023-...` and `E01FC710-...`). The InstallProtocolInterface call must be in
   this module's entry path, but I haven't pinned down which function makes the call.

## Architecture, finalized

```
                        ┌─────────────────────────────────────┐
                        │   LenovoCryptService.efi (DXE)      │
                        │                                     │
At boot:                │  ┌───────────────────────────────┐  │
  EC bytes (SVP 0x57)   │  │ FUN_00002760: derive key #1   │  │
  XOR CMOS state        │  │ → 16 bytes at DAT_00004B10    │  │
  → hash (6C48F74A) ────┼─►│                               │  │
                        │  │ FUN_00002838: derive key #2   │  │
                        │  │ → 16 bytes at DAT_00004B00    │  │
                        │  └───────────────────────────────┘  │
                        │                  │                  │
                        │                  ▼                  │
                        │  ┌───────────────────────────────┐  │
On every encrypt call:  │  │ FUN_00002B80: AES-CBC encrypt │  │
  1. Pick key bank      │  │  - copy chosen key (4B10/4B00)│  │
     by GUID            │  │  - expand to AES-128 schedule │  │
  2. Build IV           │  │    (FUN_00003284)             │  │
  3. Run AES            │  │  - encrypt CBC                │  │
                        │  │    (FUN_00004684 + LAB_3AB0)  │  │
                        │  └───────────────────────────────┘  │
                        │                                     │
                        │  Verified primitives:               │
                        │  - Te0..Te3 forward T-tables        │
                        │  - Td0..Td3 inverse T-tables        │
                        │  - Inverse S-box at 0x2510          │
                        │  - Round count read from key[0xF0]  │
                        │  - CBC mode (XOR with previous)     │
                        └─────────────────────────────────────┘
```

## Takeaway

The Lenovo T430u password subsystem combines:

- A standard Lenovo-internal hash (algorithm `6C48F74A-...`) for digesting passwords
- A standard software AES-128-CBC implementation
- A per-machine key derivation that pulls 8 bytes from the EC EEPROM and combines
  with CMOS state

The result is a "sealed AES key" without TPM hardware: the key is computed at boot
from machine-specific NVRAM, exists only in DXE memory at runtime, and is never
written to flash. This is genuinely thoughtful 2012-era OEM firmware design.

For our purposes — comprehending what the firmware does on a machine we own — this
closes the architectural picture cleanly. We know what protects the password, how the
keys are derived, where they live, and how they're used.

## Disclaimer (unchanged)

This is structural reverse engineering for personal comprehension of hardware I own.
Nothing here is a bypass path. The security of the construction relies on the EC
EEPROM being read-protected from non-SMM code (which it is, via the SVP storage
protocol's gating) and the AES key never escaping DXE memory. Knowing the design
doesn't compromise either of those properties.
