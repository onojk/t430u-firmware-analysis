# LenovoSvpManagerSmm — Password Verification Path

## TL;DR

`LenovoSvpManagerSmm.efi` is where the **per-machine binding** for the T430u SVP lives. The verification primitive is a `memcmp` against a 16-byte secret loaded from EC RAM at boot. The hash construction in `LenovoCryptServiceSmm.efi` is per-machine-independent — what makes the password unique to the machine is the *comparison target*, not the hash.

The full picture:

| Layer | Module | What it does | Per-machine? |
|---|---|---|---|
| Hash | `LenovoCryptServiceSmm.efi` | `SHA-1(SHA-1(password)[0..7] \|\| zeros)` truncated to 8/12 bytes | No |
| Verify | `LenovoSvpManagerSmm.efi` SMI 0x05 | `memcmp(7 bytes from SMI buffer, EC_secret[0..7])` | **Yes** — EC secret |
| Lockout | `LenovoSvpManagerSmm.efi` | 3-strikes counter, persisted to UEFI variable `LenovoScratchData` | Persistent across reboots |

This closes the "where is the per-machine binding for SVP" question that was opened by the salt resolution in `cryptservice_smm_handlers.md` — candidate #2 from that addendum (EC-stored digest the comparison runs against) is now confirmed.

## Provenance

Built from Ghidra disassembly of `LenovoSvpManagerSmm.efi` after manually creating functions at `0x520`, `0x6b4`, and `0x9a0` (Ghidra auto-analysis missed all three because they're reachable only through SMI handler registration callbacks or function-pointer table dispatch).

`.text` size: `0xb80` (~2.9KB). 13 functions total.

## The EC secret loader (FUN_00000830)

Called from entry point at `0x694` as the last init step. Reads a 16-byte per-machine secret from the EC and stashes it in BSS for use by the verification handler.

Pseudocode:

    FUN_00000830():
        DAT_da0 = 0;                 // clear state flag word
        DAT_d98 = 16;                // size = 16
        memset(&DAT_d80, 0, 17);     // zero the receive buffer
        DAT_da8 = 0;                 // clear attempt counter
        DAT_da4 = 0;                 // clear secondary counter

        BX = 0;                      // checksum accumulator
        for (offset = 0x10; offset < 0x20; offset++) {
            // EC mailbox protocol method 0:
            //   call(this, command=0x57, ec_offset, &out_byte)
            proto = DAT_db8;          // 0DE8BACF — EC mailbox protocol
            proto[0](proto, 0x57, offset, &out_byte);
            DAT_d80[offset - 0x10] = out_byte;
            BX += out_byte;
        }

        // Read stored checksum byte from EC offset 2:
        proto[0](proto, 0x57, 2, &expected_checksum);

        if (expected_checksum == BL):
            if (expected_checksum != 0):
                DAT_da0 |= 1;          // SET "EC secret valid"
                return;
            if (BX == 0):
                return;                // all-zero EC: leave flag clear
        else if (expected_checksum == BL - 0x56):
            DAT_da0 |= 1;              // alternative checksum form — also valid
            return;

        // Mismatch — wipe buffer
        memset(&DAT_d80, 0, 17);
        return 0;

Key facts:

- EC secret lives at **EC RAM offsets `0x10` through `0x1F`** (16 bytes).
- Checksum byte stored separately at **EC offset `0x02`**.
- Two valid checksum forms accepted: exact match, or match minus `0x56`. Reason for the alternative is unknown — possibly a versioning marker or "secret not yet provisioned" signal.
- On mismatch: cached buffer wiped, `DAT_da0` bit 0 stays clear ("no valid secret").
- The 8-byte CMOS region at `0xB0-0xB7` (managed by `LenovoCryptServiceSmm.efi`'s `73E47354` protocol) is **not** the same as this 16-byte EC secret. Two separate per-machine storage locations exist.

## SMI handler 0x05 (the verification entry point)

Registered against the SMI handler registry protocol `9F5E8C5E`. This is the function the DXE-side password code calls to verify a password.

Pseudocode:

    // SMI 0x05 — at RVA 0x520
    //
    // SMI buffer layout (uint *param_1):
    //   smi_buf[0]    = state/result word (output)
    //   smi_buf[+4..+a] = 7 bytes of caller-supplied data (input)

    handler_0x05(uint *smi_buf):
        state = FUN_00000a38();      // get current state flags
        smi_buf[0] = state;
        if (state & 1) return;       // EC secret invalid → bail
        if (state & 8) return;       // already locked out → bail

        // Compose 7 bytes from SMI buffer into a stack-local work area:
        work[0..4] = *(uint32*)(smi_buf + 4);
        work[4]    = smi_buf[8];
        work[5]    = smi_buf[9];
        work[6]    = smi_buf[0xa];

        result = FUN_000006b4(
            rcx = &GUID(0x260),      // identifier — the protocol GUID this module installs
            rdx = work,              // 7-byte input buffer
            r8  = NULL,
            r9  = 1                  // mode = 1 (compare-only, no pre-hash)
        );

        if (result == 0):                 smi_buf[0] &= ~4;   // clear failure bit
        else if (result == 0x80000008):   smi_buf[0] |= 0xc;  // set fail + lockout bits
        else:                             smi_buf[0] |= 4;    // set generic failure bit
        return;

The 7-byte field at `smi_buf[+4..+b]` is what the DXE caller hands in. Almost certainly this is derived from CryptServiceSmm's hash output — though the byte alignment doesn't match exactly (CryptServiceSmm SMI 0x83 returns 8 bytes; this reads 7). Tracing the DXE-side caller would resolve this.

## The verification work function (FUN_000006b4)

This is where comparison-against-EC-secret and lockout management actually happen. Called by handler 0x05 with mode=1.

Pseudocode:

    uint32 FUN_000006b4(guid_addr, work_buf, _, mode):
        if (mode == 1): size = 7;  else: size = 16;
        DAT_db0 = size;

        if (DAT_da8 >= 3):
            return 0x80000008;            // ALREADY LOCKED OUT

        char local[size];
        memset(local, 0, ...);
        memcpy(local, work_buf, size);    // copy caller's input

        if (mode != 1):                   // mode 0 path — pre-hash the input
            result = FUN_000009a0(local); // SHA-1(local[0..7] || DAT_d30[0..10])
            if (result == 0x80000000):
                return 0x80000000;        // hash protocol unavailable

        // Both modes converge here:
        if (memcmp(local, &DAT_d80, size) == 0):
            // ─── MATCH ───
            DAT_da0 |= 2;                 // set "verified" bit
            DAT_da8 = 0;                  // reset attempt counter
            DAT_da4 = 0;                  // reset secondary counter
            result = 0;
        else:
            // ─── MISMATCH ───
            if (mode == 2):
                DAT_da4 += 1;
                if (DAT_da4 & 1) goto skip_increment;
            DAT_da8 += 1;                 // bump primary attempt counter
            if (DAT_da8 >= 3):
                DAT_da0 |= 8;             // SET LOCKOUT BIT
            result = 0x80000001;

        // Both paths persist state to UEFI variable LenovoScratchData:
        proto = DAT_dc0;                  // CDFCA3E8 — SMM Variable Services protocol
        GetVariable("LenovoScratchData", &GUID(67C3208E-...), &attrs, &size=32, &buf);
        if (succeeded):
            buf.byte_at(some_offset) = 1; // update one byte
            SetVariable("LenovoScratchData", &GUID(67C3208E-...), attrs, 32, buf);

        return result;

Three observations worth flagging:

1. **The lockout is local to the SMM session counter `DAT_da8`** — but it's also persisted via `LenovoScratchData`, which means a reboot does not necessarily reset the lockout. The persistent state survives across boots.
2. **Mode 2 has a 50% counter slowdown** (`if (DAT_da4 & 1) skip_increment`). Speculative: this might be a softer failure mode for a different password type (e.g. POP vs SVP), or for a "verify-without-counting" path. Handler 0x05 only ever sends mode=1, so we'd need to find the mode=2 caller to confirm.
3. **Mode 0 calls `FUN_000009a0` (salted SHA-1) before comparing.** This is the "I have raw input, hash it first, then compare against the 16-byte EC secret" variant. Handler 0x05 sends mode=1 (pre-hashed), so the DXE caller is responsible for hashing. Some other path uses mode=0 to do the hashing in SMM.

## The salted-SHA-1 wrapper (FUN_000009a0)

Structurally identical to `FUN_000009e4` in CryptServiceSmm — same construction, same shape, different module. Called only from the mode=0 path of `FUN_000006b4`.

Pseudocode:

    FUN_000009a0(buf):
        char composition[17];
        char hash_out[32];
        memset(composition, 0, 17);
        memset(hash_out, 0, 32);
        memcpy(composition,     buf,        7);     // first 7 bytes from caller
        memcpy(composition + 7, &DAT_d30,  10);     // 10-byte salt

        proto = DAT_d28;                            // FE2965BB — hash protocol
        if (!proto) return 0x80000000;
        proto[0](proto, composition, 17, hash_out); // SHA-1(composition)

        memcpy(buf, hash_out, DAT_db0);             // copy back size bytes (7 or 16)
        return 0;

The 10-byte salt at `DAT_d30` has no writer in this module — exact same situation as `DAT_e18` in CryptServiceSmm (see `cryptservice_smm_handlers.md`'s salt-resolution addendum). The salt is permanently zero. The construction reduces to `SHA-1(buf[0..7] || zeros)`, providing domain separation only.

This **strengthens the salt-resolution finding**: it's not a bug or a missed code path in one module. The "salted SHA-1 with no writer" pattern appears in **both** SMM modules with **identical structure**. It's a deliberate (or accidentally consistent) design choice across the SVP subsystem.

## GUID corrections

Two GUIDs in the project's existing notes were misclassified. This analysis corrects them, and identifies one additional GUID not previously annotated.

### `FE2965BB-5A8E-43B3-AEDD-ABCC63003D14` — hash protocol, NOT a "gating event"

Earlier notes (`cryptservice_smm_analysis.md`, `svp_manager_smm_analysis.md`, `hash_algorithm_investigation.md`) called this a "gating event GUID" or "PasswordCp event." It is actually a **SHA-1 hash protocol** consumed via SMM. Method 0 takes `(this, input_buf, size, output_buf)` and computes a SHA-1 digest. Producer module is currently unidentified.

### `CDFCA3E8-C45C-47BA-BA50-F5C2EAE33E7E` — SMM Variable Services protocol

Not previously annotated. This protocol is consumed by `FUN_000006b4` to GetVariable / SetVariable on `LenovoScratchData`. Method 0 = GetVariable, method `+0x10` = SetVariable. Almost certainly Phoenix's wrapper around `EFI_SMM_VARIABLE_PROTOCOL` or equivalent.

### `67C3208E-4FCB-498F-9729-0760BB4109A7` — `LenovoScratchData` vendor GUID

Not previously annotated. Vendor GUID for the UEFI variable named `LenovoScratchData`. The variable is 32 bytes and persists lockout / attempt-counter state across reboots.

## Functions in this module — reference table

| RVA | Name | Purpose |
|---|---|---|
| `0x520` | `LenovoSvpManagerSmm.efi` (Ghidra named) | SMI 0x05 handler — DXE → SMM verification entry |
| `0x59c` | `entry` | SMM driver entry point |
| `0x6a8` | `FUN_000006a8` | Protocol method 1 — read state flag `DAT_da0` |
| `0x6b4` | `FUN_000006b4` | Protocol method 2 — verification + lockout management |
| `0x830` | `FUN_00000830` | Init: load 16-byte EC secret with checksum verification |
| `0x930` | `FUN_00000930` | Query something via the variable services protocol (returns a byte) |
| `0x984` | `FUN_00000984` | Init: zero the 10-byte salt at `DAT_d30` |
| `0x9a0` | `FUN_000009a0` | Salted-SHA-1 wrapper (mirror of CryptServiceSmm's `FUN_000009e4`) |
| `0xa38` | `FUN_00000a38` | Get state flags (called by handler 0x05) |
| `0xa8c` | `FUN_00000a8c` | Entry-point prerequisite gate |
| `0xbe4` | `FUN_00000be4` | `memcmp` (8-byte fast path + byte fallback) |
| `0xc40` | `FUN_00000c40` | `memcpy` (forward/reverse-aware) |
| `0xc84` | `FUN_00000c84` | `memset` wrapper |
| `0xc9c` | `FUN_00000c9c` | `memset` (raw byte fill) |

## State globals — reference table

| Address | Name | Role |
|---|---|---|
| `DAT_d20` | SMI handler registry protocol pointer | LocateProtocol(`9F5E8C5E`) result |
| `DAT_d28` | hash protocol pointer | LocateProtocol(`FE2965BB`) result |
| `DAT_d30` | 10-byte salt buffer | Zero-init at boot, never written. Read by `FUN_000009a0` |
| `DAT_d40` | SMM BootServices pointer | Cached at entry from SmmSystemTable+0x60 |
| `DAT_d80` | **16-byte EC secret** | Loaded from EC RAM offsets `0x10-0x1F` at boot |
| `DAT_d98` | EC secret size = 16 | Set at init |
| `DAT_da0` | state flag word | Bit 0 = secret valid, bit 1 = verified, bit 3 = lockout |
| `DAT_da4` | secondary counter | Increments on mode=2 failure (every other attempt) |
| `DAT_da8` | **attempt counter** | Increments on each mismatch; >=3 triggers lockout |
| `DAT_db0` | working size = 7 or 16 | Set per-call by `FUN_000006b4` based on mode |
| `DAT_db8` | EC mailbox protocol pointer | LocateProtocol(`0DE8BACF`) result |
| `DAT_dc0` | SMM Variable Services protocol pointer | LocateProtocol(`CDFCA3E8`) result |

## Threads to pull next

1. **The 7-vs-8 byte alignment between CryptServiceSmm output and SvpManagerSmm input.** CryptServiceSmm SMI 0x83 returns 8 bytes; SvpManagerSmm SMI 0x05 reads 7. Either there's a 1-byte trim by the DXE caller, or the windowing is different. Reading `LenovoSvpManagerDxe.efi` and `LenovoPasswordCp.efi` (already extracted, not yet analyzed in detail) would resolve this.
2. **The mode=0 caller of `FUN_000006b4`.** Handler 0x05 always sends mode=1. Some other path sends mode=0 to trigger the salted-SHA-1 step before comparison. Likely an internal use within SvpManagerSmm itself, or a different SMI handler we haven't traced.
3. **The producer module of `FE2965BB`.** Some module installs this SHA-1-as-protocol service that both CryptServiceSmm-side and SvpManagerSmm-side consumers use. Worth identifying for completeness — likely a small standalone hash service driver.
4. **The exact write pattern to `LenovoScratchData`.** The handler reads 32 bytes, modifies "one byte" at "some offset," writes back. Tracing exactly which byte represents what (lockout state? attempt count? success flag?) would let us understand the persistent SVP state model fully.

## What this resolves at the project level

This closes two open questions from the start of the project:

- **"How does the A/B Supervisor Password redundancy actually work?"** — partially. The verification path is now mapped end-to-end. The "A/B redundancy" likely refers to the dual representation in CMOS (8 bytes at `0xB0-0xB7`) vs EC (16 bytes at `0x10-0x1F`); these are two separate per-machine storage regions accessed by two separate protocols.
- **"What exactly triggers the 0177/0199 errors and the retry counter / lockout logic?"** — `DAT_da8 >= 3` triggers lockout (`DAT_da0 |= 8`). The error code `0x80000008` returned by `FUN_000006b4` when locked out is what the DXE-side caller sees. The visible 0177/0199 errors are most likely produced by the DXE-side caller in response to that error code.
