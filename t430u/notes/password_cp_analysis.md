# T430u Password Character Processing Module Analysis

## Module
- **File**: `LenovoPasswordCp.efi` (extracted from the 4MB BIOS dump)
- **Size**: 3,520 bytes
- **Type**: PE32+ x86-64 EFI Boot Service Driver
- **Module name**: Password Cp DXE — "Password Character Processing"

## Big picture

This is the user-facing side of the password subsystem. Where `LenovoSvpManagerDxe` ferries already-validated password data between EFI variables and SMM, **this module is what reads the actual keystrokes** when you type your password at the BIOS prompt, validates each character, builds the input string, then runs it through a two-stage hashing pipeline before passing the result on for comparison.

It's the smallest of the three Lenovo modules we've extracted (3.5 KB) but arguably the most informative, because it tells us:

1. **Exactly which characters the BIOS accepts in a password** — far more restrictive than you'd expect.
2. **The maximum password length** — 64 characters, hardcoded.
3. **The shape of the hashing system** — two sequential transforms producing a 16-byte digest, but with the actual algorithms hidden behind protocol GUIDs.
4. **The keystroke timeout / autorepeat behavior** — visible directly in the code.
5. **Which EFI variables hold the runtime state** — including a previously-unseen `LenovoLoginTypeVar`.

## Strings

Just one string in the entire module:

| Offset | String |
|---|---|
| `0x3A0` | `LenovoLoginTypeVar` (UTF-16) |

This is an EFI variable name. The module reads or writes a variable by this name — almost certainly to track which password type is being entered (POP vs SVP vs HDD). This is the kind of state that has to survive across the brief window between password entry and the next-stage handler running.

No error strings, no prompt strings, no diagnostic text. The visible UI ("Enter Password" prompt, the asterisks as you type, the failure beep) is all rendered by another module — probably the Phoenix Setup Browser. This module is the silent worker behind that UI.

## GUIDs

Ten GUIDs are embedded in the data section. **Four of them are shared with `LenovoSvpManagerDxe`**, confirming the modules talk to a common pool of SVP protocols:

| Offset | GUID | Notes |
|---|---|---|
| `0x2B0` | `13DC32CC-A8DF-425A-B775-F16C14B9C7D1` | Same as SvpManager 0x2E8 |
| `0x2C0` | `2846B2A8-77C8-4432-86EC-199F205D37CA` | Same as SvpManager 0x2F8 |
| `0x2D0` | `65FB555D-5CCA-40C3-9967-227988288DD8` | Same as SvpManager 0x308 |
| `0x2E0` | `73E47354-B0C5-4E00-A714-9D0D5A4FDBFD` | Same as SvpManager 0x318 |
| `0x2F0` | `FE2965BB-5A8E-43B3-AEDD-ABCC63003D14` | New — not in SvpManager |
| `0x300` | `293D0637-6A70-4B4B-B333-7571C79EBEF6` | New |
| `0x310` | `56350810-2CB2-4AA0-96D2-66D1B8E1AAC2` | New |
| `0x320` | **`E01FC710-BA41-493B-A919-53583368F6D9`** | Hash stage 2 protocol |
| `0x330` | `2CF8CC1B-58DF-4646-8DEE-7CEFAB10F782` | Setup browser proto |
| `0x340` | **`E3ABB023-B8B1-4696-98E1-8EEDC3D3C63D`** | Hash stage 1 protocol |

The two boldface GUIDs are the most consequential — they identify the hash transform protocols. Tracking down which other modules in the BIOS install these GUIDs (using `uefifind`) would lead directly to the hash algorithm implementations.

## Function map

```
LenovoPasswordCp.efi
├── entry()
│   ├── FUN_00000a84              ← cache RT/BS pointers (init)
│   ├── FUN_00000b4c              ← LocateProtocol(GUID@0x2e0) → DAT_00000c90
│   ├── FUN_00000b10              ← LocateProtocol(GUID@0x310) → DAT_00000c98 (UI/render)
│   ├── FUN_00000ae0              ← LocateProtocol(GUID@0x320) → DAT_00000ca0 (HASH stage 2)
│   ├── FUN_00000aa4              ← LocateProtocol(GUID@0x340) → DAT_00000ca8 (HASH stage 1)
│   └── BootServices->RegisterProtocolNotify(GUID@0x2b0, CALLBACK=0x240, ...)
│        — registers itself with the setup browser system
│
├── FUN_00000444                  ← getter callback — exposed via the registered protocol
│                                    returns DAT_00000cd0 (state) and conditionally CopyMem 16 bytes
│
├── FUN_000004dc                  ← THE PASSWORD INPUT LOOP (main user-facing function)
│   ├── FUN_000006c4              ← read one keystroke (with timer/timeout logic)
│   ├── FUN_00000a00              ← character validator (allowed-charset check)
│   ├── FUN_00000a58              ← UI update (cursor position / asterisk display)
│   ├── FUN_00000a38              ← UI update (input rejected — beep / flash?)
│   ├── FUN_0000085c               ← state machine update (called on special key)
│   └── FUN_0000089c              ← THE HASH PIPELINE (called on ENTER)
│
├── FUN_0000089c                  ← password → 16-byte digest
│   ├── [DAT_00000ca8] (hash stage 1, GUID E3ABB023-...)
│   └── [DAT_00000ca0] (hash stage 2, GUID E01FC710-...)
│
└── helpers (init / small utility functions):
    FUN_00000a84, FUN_00000aa4, FUN_00000ae0, FUN_00000b10, FUN_00000b4c
```

## The character whitelist

`FUN_00000a00` is a single-purpose function: given a Unicode codepoint, return TRUE if it's an allowed password character. The code is simple enough to read directly:

```
FUN_00000a00(ushort ch):
  if (ch >= '0' && ch <= '9') return TRUE   // 0x30..0x39
  if (ch >= 'a' && ch <= 'z') return TRUE   // 0x61..0x7A
  if (ch >= 'A' && ch <= 'Z') return TRUE   // 0x41..0x5A
  if (ch == ' ')              return TRUE   // 0x20
  if (ch == ';')              return TRUE   // 0x3B
  return FALSE
```

**Allowed characters: 0–9, A–Z, a–z, space, semicolon.** That's it.

This is much more restrictive than a typical password field. No `!@#$%^&*` — none of those work in a T430u BIOS password. The semicolon is an odd inclusion (probably for compatibility with Lenovo's deployment-tools scripted-config format, which uses `;` as a separator). Space being allowed is also unusual.

If you ever wondered why your "stronger" password full of symbols doesn't work in BIOS setup but the alphanumeric one does — this is why. The acceptance is happening here, character by character, before the password ever reaches the hash function.

## The keystroke loop

`FUN_000006c4` is the keystroke reader. It uses standard UEFI Simple Text Input:

```
SetTimer(timer, REL_TIME, 0x32cfd0)        ; ~333ms timeout (3,329,488 × 100ns)
WaitForEvent({key_event, timer_event})     ; wait for either
ReadKeyStroke()                             ; if key, get the char
... reset/cancel timer ...
```

The timeout window is **333 milliseconds**. After receiving a keystroke, the function does some autorepeat-detection bookkeeping (the divide-by-1000 with reciprocal multiplication is a compiler optimization for converting microseconds to milliseconds). This is what gives the password prompt its "feel" — keys don't repeat until you've held them for ~333ms, which is a typical autorepeat delay.

## The input loop

`FUN_000004dc` is the main loop. It reads keys, dispatches by scancode:

| Scancode | Meaning |
|---|---|
| `0x0B` | ENTER — submit password |
| `0x08` | BACKSPACE — delete last char |
| `0x0D` | (special — invokes `FUN_0000085c` which advances state) |
| anything else | route through `FUN_00000a00` charset check |

**Maximum password length: 0x40 = 64 characters.** Hardcoded in the loop (`CMP EBX, 0x40`). Past 64, additional keystrokes are silently ignored (the function calls `FUN_00000a38`, the "rejected input" UI handler — likely a beep).

The buffer (`local_88`) is allocated as 128 bytes on the stack — which is exactly 64 wide-characters × 2 bytes each. UTF-16 throughout, in keeping with UEFI convention.

When ENTER is pressed and the buffer has at least one character, control transfers to `FUN_0000089c` — the hash pipeline.

## The hash pipeline (FUN_0000089c)

This is the heart of password verification. The function:

1. Allocates three 64-byte buffers on the stack (`local_88`, `local_48`, `local_a8`).
2. Walks the user's input wide-string and **copies only the low byte of each wide char** into `local_88` — converting UTF-16 to ASCII (since all valid characters are ≤0x7A, this is lossless).
3. Calls `[DAT_00000ca8](local_88, local_48, 0x40)` — first transformation. Input is the 64-byte ASCII buffer, output goes to `local_48`.
4. Calls `[DAT_00000ca0](local_48, local_a8, 0x40)` — second transformation. Input is the result of stage 1, output goes to `local_a8`.
5. Calls `CopyMem(output_arg, local_a8, 16)` — copies the first 16 bytes of stage-2 output into the caller's output buffer.
6. Zeros all three local buffers (good-hygiene cleanup before return).

**The hash is two stages, sequentially applied, producing a 16-byte digest.**

Things this analysis cannot tell us:
- What algorithm stage 1 uses (GUID E3ABB023-B8B1-4696-98E1-8EEDC3D3C63D)
- What algorithm stage 2 uses (GUID E01FC710-BA41-493B-A919-53583368F6D9)
- Whether either stage is keyed (they could be HMAC-style with a machine-specific key, e.g. derived from EC NVRAM)

To learn those, we'd need to find the modules that *install* these protocols. Those modules are almost certainly elsewhere in the BIOS, possibly as SMM drivers (`*Smm.efi`).

## What this tells us about T430u password security

Putting this together with what we found in `LenovoSvpManagerDxe`:

```
User types password at BIOS prompt
  ↓
LenovoPasswordCp.efi (this module):
  ↓ FUN_00000a00 validates each character (a-z, A-Z, 0-9, space, semicolon only)
  ↓ FUN_000004dc accumulates up to 64 chars
  ↓ On ENTER:
  ↓ FUN_0000089c hashes the password through two protocol-provided stages
  ↓ Result: 16-byte digest
  ↓
[passes the 16-byte digest to a caller, presumably SetupCp]
  ↓
[that caller eventually invokes the SVP comparison via SMI]
  ↓
SMM handler:
  ↓ Reads the stored hash from the EC EEPROM (via 0x57 protocol)
  ↓ Compares the typed-password's digest to the stored digest
  ↓ Returns match/no-match
  ↓
LenovoSvpManagerDxe.efi handles the storage validation (0177 / 0199 errors)
```

**The password itself never crosses an SMI boundary.** Only its 16-byte digest does. Which means even if you could intercept the SMI payload, you wouldn't see a typed password — you'd see a digest, which without knowing the two transform algorithms (and any salts/keys) would not be straightforward to reverse.

That said: the digest is only 16 bytes. With **64 characters from a 65-character alphabet** as the input space, the theoretical password space is huge. But humans don't pick random 64-char passwords — they pick 8-character ones. With a deliberately chosen and easily computed digest function (which Lenovo's likely is, since this is firmware-era code), a known-plaintext or rainbow-table attack against typical user passwords is plausible **if you have the digest**, which would require physical access to the EC EEPROM.

This is why the practical attack on forgotten ThinkPad SVP is still: pull the EC EEPROM chip off the board, read it externally, then either rewrite it with a known-good blob or run cracking against the digest. None of that requires breaking the BIOS — the BIOS tells you exactly how the system works.

## What's interesting that we didn't expect

**The LoginTypeVar variable.** `LenovoLoginTypeVar` is referenced by name in this module. It's not a variable that's been documented anywhere I'm aware of in the ThinkPad community. It might track:
- Whether the boot flow needs POP, SVP, HDD, or some combination
- A "remember me until next reboot" state
- Whether to show different UI for setup-vs-boot password entry

Worth checking what other modules read or write this variable — `uefifind` against the variable name in UTF-16 would find them quickly.

**Two-stage hash, not one.** I was expecting a single transform. Two stages with different protocol GUIDs is unusual — possibly:
- Stage 1: a pre-hash normalization (case-fold? salt-mix?)
- Stage 2: the actual digest function

Or possibly stage 1 is a deterministic transformation that's machine-tied (e.g., XOR with a per-machine key derived from EC NVRAM), making the result non-portable between machines. That would be a clever defense against rainbow tables — you can't precompute, because each machine's stage-1 output depends on a key only it has.

## Threads to pull next

In rough priority order:

1. **`uefifind` for the two hash-stage GUIDs.**
   - `E3ABB023-B8B1-4696-98E1-8EEDC3D3C63D` — find what installs this
   - `E01FC710-BA41-493B-A919-53583368F6D9` — find what installs this
   These are the prize — the modules that actually compute the hash.

2. **`uefifind` for `LenovoLoginTypeVar`** as a UTF-16 string — see what else in the BIOS reads/writes this variable.

3. **The four shared GUIDs** between SvpManager and PasswordCp (0x13DC32CC, 0x2846B2A8, 0x65FB555D, 0x73E47354) — finding their implementer modules would give us the rest of the SVP architecture.

4. **The Phoenix Setup Browser modules.** This driver registers itself as a protocol consumer of `0x2B0` (`13DC32CC-...`) — that protocol is probably the setup-browser callback registry. Tracing those callbacks would show us how the password prompt is presented in the BIOS UI.

## What this isn't

A vulnerability disclosure or a tool for unauthorized access. The module's behavior is normal and expected for an OEM password manager of this era. The interest here is purely architectural: understanding how a 12-year-old industrial firmware chooses to handle credentials. The lessons (limited charset, hardcoded length, two-stage protocol-mediated hash, EC-side comparison) are documented as much for posterity as for use.
