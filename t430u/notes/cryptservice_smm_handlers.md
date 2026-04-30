# LenovoCryptServiceSmm SMI Handlers — Stage 1/Stage 2 Resolution

## TL;DR

The "two-stage password hash" framing in earlier notes was wrong. `LenovoCryptServiceSmm.efi` does **not** implement two distinct cryptographic stages. It implements **one** hash construction, exposed via three SMI commands that differ only in I/O shape:

| SMI cmd | Handler | Input shape | Output bytes |
|---|---|---|---|
| `0x83` | `FUN_00000560` | streamed 8x8-byte chunks | 8 bytes |
| `0x8F` | `FUN_000006ae` | streamed 8x8-byte chunks | 12 bytes |
| `0x90` | `LAB_00000800` | single-shot, caller pointer | (writes back via pointer) |

The construction in all three cases:

    hash1 = SHA-1(input_64_bytes)              # 20 bytes
    truncated = hash1[0..7]                    # 7 bytes
    salted = truncated || DAT_e18[0..10]       # 17 bytes
    hash2 = SHA-1(salted)                      # 20 bytes
    output = hash2[0..N]                       # N=8, 12, or 20 depending on caller

The previous mapping `E3ABB023 = Stage 1` and `E01FC710 = Stage 2` is therefore a misreading. Both GUIDs sit in this module's `.text` GUID block but are **not installed as DXE protocols** by this module's entry point — entry only installs `73E47354` (the unrelated CMOS-management protocol). The two GUIDs are likely identifiers passed through the SMI buffer or used by callers to select between the 8-byte and 12-byte output forms.

## Provenance

This writeup is built from Ghidra's disassembly of `LenovoCryptServiceSmm.efi` after manually creating functions at `0x560`, `0x6ae`, and `0xabc` (Ghidra's auto-analysis missed all three because they are reachable only through SMI handler registration callbacks, which Ghidra cannot statically resolve).

The earlier `hash_algorithm_resolved.md` is unaffected — its findings on `SystemCryptSvcRt.efi`'s SHA-1 implementation remain correct. This note adds detail at a layer above that one: how the SHA-1 primitive is composed into the password-hash construction.

## The streaming handlers (0x83 and 0x8F)

Both handlers share state:

- `DAT_00000dd0` (a.k.a. `state`) — 64-byte BSS buffer holding the accumulated input across SMI calls.
- `DAT_00000dc8` — uint32 chunk counter at the head of the state region (sits 8 bytes before `dd0` due to layout, but Ghidra labels them separately).

Both handlers expect an SMI buffer with at least these fields:

    struct smi_buf {
        uint32 field_0;     // status / return code
        uint32 field_4;     // 4 bytes of input (and 4 bytes of output, returned)
        uint32 field_8;     // 4 bytes of input (and 4 bytes of output, returned)
        uint32 field_C;     // (unused?)
        uint32 field_10;    // chunk index (0..7) on input; reset to 0 on return
        uint32 field_14;    // (handler 0x8F only) 4 bytes of additional output
    };

### Pseudocode for handler 0x83 (FUN_00000560)

    undefined8 FUN_00000560(uint32 *smi_buf)
    {
        if (smi_buf->field_10 == 0) {
            // INIT path: caller starting a new operation
            memset(&DAT_dd0, 0, 0x41);     // zero 65 bytes of state
            memset(&local_40, 0, 0x21);    // zero 33 bytes on stack
            DAT_dc8 = 0;                   // counter = 0
            // fall through to chunk_path
        } else {
            chunk_idx = smi_buf->field_10;
            if (chunk_idx >= 8)            return error_0x80000000;  // bounds
            if (chunk_idx != DAT_dc8)      return error_0x80000000;  // ordering
            // fall through to chunk_path
        }

    chunk_path:
        offset = chunk_idx * 8;
        memcpy(&state[offset    ], &smi_buf->field_4, 4);
        memcpy(&state[offset + 4], &smi_buf->field_8, 4);
        DAT_dc8 += 1;

        if (DAT_dc8 != 8) {
            // Not the final chunk — acknowledge and wait for next
            smi_buf->field_0  = 0;
            smi_buf->field_10 = 0;
            return 0;
        }

        // Final chunk — full 64 bytes accumulated. Run the construction.
        SHA-1(state, 0x40, &local_40);     // hash1 = SHA-1(state[0..64])
        memset(&local_68, 0, 0x20);        // clear 32-byte composition area
        memcpy(&local_68, &local_40, 7);   // truncated = hash1[0..7]

        err = FUN_000009e4(&local_68);     // hash2 = SHA-1(truncated || salt[0..10])
                                           // result written back into local_68
        if (err == 0x80000000) {
            smi_buf->field_0 = 0x80000000;
            return 0;
        }

        // Return 8 bytes of digest
        memcpy(&smi_buf->field_4, &local_68 + 0, 4);
        memcpy(&smi_buf->field_8, &local_68 + 4, 4);

        DAT_dc8           = 0;             // reset counter
        smi_buf->field_0  = 0;
        smi_buf->field_10 = 0;
        return 0;

    error_0x80000000:
        smi_buf->field_0 = 0x80000000;
        return 0;
    }

### Pseudocode for handler 0x8F (FUN_000006ae)

Structurally identical to 0x83 with **one difference at the very end**: an extra `memcpy` writes 4 more bytes of digest output into `smi_buf->field_14`.

    // ... identical streaming logic through the construction ...

    // Return 12 bytes of digest (vs 8 in handler 0x83)
    memcpy(&smi_buf->field_4,  &local_68 + 0, 4);
    memcpy(&smi_buf->field_8,  &local_68 + 4, 4);
    memcpy(&smi_buf->field_14, &local_68 + 8, 4);   // <-- only in 0x8F

That is the **entire** behavioral difference between the two handlers.

## The single-shot handler (0x90, LAB_00000800)

    LAB_00000800(uint32 *smi_buf)
    {
        // SMI buffer fields:
        //   field_8  = input size (uint32)
        //   field_10 = input buffer address (32-bit physical)
        //   field_14 = output buffer address (32-bit physical, >=32 bytes)

        output_ptr = smi_buf->field_14;
        size       = smi_buf->field_8;
        input_ptr  = smi_buf->field_10;

        SHA-1(input_ptr, size, output_ptr);    // hash1 written to output[0..20]

        memset(output_ptr + 7, 0, 25);         // clear output[7..32]
        FUN_000009e4(output_ptr);              // in-place: output[0..7] is treated as
                                               // truncated hash1; result hash2 written
                                               // back to output[0..20]
        return 0;
    }

So 0x90 is the same construction without the chunk-streaming wrapper — the caller supplies a pointer to a buffer of any size and a pointer to >=32 bytes of output space, and gets the same `SHA-1(SHA-1(input)[0..7] || salt[0..10])` result.

This is the variant a runtime caller uses when it already has the full input buffered and has access to physical-address space (i.e. DXE phase before SetVirtualAddressMap, or another SMM module). The streaming variants exist for callers that can only pass small chunks through the SMI buffer.

## The salted-SHA-1 helper (FUN_000009e4)

    undefined8 FUN_000009e4(uint32 *buf)
    {
        char composition[17];   // local_28
        char hash_out[32];      // local_38

        memset(composition, 0, 17);
        memset(hash_out,    0, 32);

        memcpy(composition,     buf,        7);     // first 7 bytes from caller
        memcpy(composition + 7, &DAT_e18,  10);     // 10-byte salt

        SHA-1(composition, 17, hash_out);           // hash2 = SHA-1(comp)

        memcpy(buf, hash_out, 32);                   // copy 32 bytes back
                                                    // (only the first 20 are
                                                    //  meaningful; the trailing
                                                    //  12 are residual stack zeros
                                                    //  from the memset above)

        return 0;
    }

A small Phoenix-toolchain quirk: it copies 32 bytes of output even though SHA-1 only produces 20. The trailing 12 bytes are zeros from the prior `memset`, so the effect is harmless — but it does mean the output buffer must be at least 32 bytes, not 20.

## The salt mystery

`DAT_00000e18` is a 10-byte buffer in BSS. It is:

- **Zeroed** by `FUN_000009c8` (called from the entry point at `0x8ca`)
- **Read** by `FUN_000009e4` (the salted-SHA-1 helper)

There is **no writer** to `DAT_e18` anywhere in this module. Two possibilities:

1. **Cross-module population.** Another SMM driver writes to this address via a shared protocol or mapped pointer. The leading candidate is `LenovoSvpManagerSmm.efi`, which manages EC-stored secrets and is the natural place for a per-machine salt to originate.
2. **Always zero.** The salt is genuinely never populated, in which case the round-2 SHA-1 reduces to deterministic mixing — `SHA-1(hash1[0..7] || 0x00 * 10)` — which provides no cryptographic strength beyond the truncated hash1, only domain separation.

Resolving this requires reading `LenovoSvpManagerSmm.efi`'s disassembly (already extracted as `LenovoSvpManagerSmm.txt`). Specifically, looking for any code that writes to a 10-byte buffer and ties it to per-machine state.

## What's also in this module — the unrelated CMOS protocol

Worth noting because it has confused earlier analysis: the dispatch table at `.text:0x240` in this module is **not** part of the hash subsystem. It is the four-method protocol installed against GUID `73E47354-B0C5-4E00-A714-9D0D5A4FDBFD`, which exposes CMOS read/write/wipe of 8 bytes at offsets `0xB0–0xB7` (`FUN_00000a68`, `FUN_00000a80`, `FUN_00000abc`, `FUN_00000b10`).

The CMOS access is via the standard I/O ports `0x70/0x71` (low CMOS) and `0x72/0x73` (extended CMOS, which is where offsets >= `0x80` route). See `FUN_00000cf4` (read) and `FUN_00000d14` (write).

This protocol shares a module with the hash construction but is functionally independent. The 8-byte CMOS region at `0xB0–0xB7` is **not** the salt at `DAT_e18` (which is 10 bytes, not 8, and lives in BSS rather than CMOS). They are two separate per-machine secrets — or, more cautiously, two separate buffers where per-machine secrets *could* be stored.

## Functions in this module — reference table

| RVA | Ghidra name | Purpose |
|---|---|---|
| `0x560` | `FUN_00000560` | SMI handler 0x83: streaming hash, 8-byte output |
| `0x6ae` | `FUN_000006ae` | SMI handler 0x8F: streaming hash, 12-byte output |
| `0x800` | `LAB_00000800` | SMI handler 0x90: single-shot hash |
| `0x838` | `entry` | SMM driver entry point |
| `0x930` | `FUN_00000930` | `SHA-1(input, output, size)` via hash dispatcher |
| `0x9c8` | `FUN_000009c8` | Zero-initialize the 10-byte salt at `DAT_e18` |
| `0x9e4` | `FUN_000009e4` | `SHA-1(buf[0..7] || salt[0..10]) -> buf[0..20]` |
| `0xa68` | `FUN_00000a68` | CMOS protocol slot 0 (4-arg adapter to `0x930`) |
| `0xa80` | `FUN_00000a80` | CMOS protocol slot 1: read 8 bytes from CMOS `0xB0–0xB7` to cache |
| `0xabc` | `FUN_00000abc` | CMOS protocol slot 2: commit cached 8 bytes back to CMOS |
| `0xb10` | `FUN_00000b10` | CMOS protocol slot 3: zero CMOS `0xB0–0xB7` |
| `0xb40` | `FUN_00000b40` | `memcpy` (dst, src, size) |
| `0xb84` | `FUN_00000b84` | `memset` wrapper (calls `0xd40`) |
| `0xb9c` | `FUN_00000b9c` | Entry-point prerequisite gate (locates 3 SMM protocols) |
| `0xcf4` | `FUN_00000cf4` | CMOS read via ports `0x70/0x71` or `0x72/0x73` |
| `0xd14` | `FUN_00000d14` | CMOS write via ports `0x70/0x71` or `0x72/0x73` |
| `0xd40` | `FUN_00000d40` | `memset` (dst, byte, count) |

## Threads to pull next

1. **Find the writer of `DAT_e18`.** Search `LenovoSvpManagerSmm.txt` and possibly other SMM drivers for any reference to a 10-byte buffer that gets populated from EC reads or CMOS or a per-machine source. This is the single biggest open question for the password subsystem.

2. **Identify the callers of SMI 0x83 / 0x8F / 0x90 from DXE.** That tells us which DXE module(s) consume the hash construction and how — in particular, what data they feed in (raw password? pre-hashed? padded?) and what they do with the 8/12-byte output (compare against stored digest in CMOS/EC? feed into AES key derivation?).

3. **Reconcile the GUIDs.** `E3ABB023` and `E01FC710` are present in this module's `.text` GUID block but not installed by entry. Are they SMI command identifiers, or installed by another module that wraps these SMI calls behind protocol interfaces? Worth grepping the other DXE modules for both.

4. **Resolve the architectural picture.** With Stage 1/Stage 2 collapsed to one construction + truncation, the original "two-stage hash pipeline" diagram in `password_cp_analysis.md` may need revision. Either the DXE-side caller invokes both lengths for different purposes (e.g. 8-byte for storage, 12-byte for AES key seeding), or one of the two is unused in the current firmware.

## Addendum: salt resolution — DAT_e18 is permanently zero

The "salt mystery" question above is resolved: there is no writer to `DAT_e18` anywhere in the firmware. The 10-byte buffer is set to zero once at module load by `FUN_000009c8` and never touched again.

### Evidence

In `LenovoCryptServiceSmm.efi`:

- Total xrefs to `DAT_e18`: 2.
- Writer: `FUN_000009c8` (zero-initialization, called once from entry at `0x8ca`).
- Reader: `FUN_000009e4` (the salted-SHA-1 helper).
- No other code in this module references the address. This holds even after manually disassembling SMI handlers `0x83`, `0x8F`, `0x90` (none of which touch the salt).

In `LenovoSvpManagerSmm.efi`:

- Module's entry point installs one protocol (`65FB555D`), locates four (`0DE8BACF` EC mailbox, `9F5E8C5E` SMI registry, `FE2965BB` gating event, `CDFCA3E8` unknown), and registers SMI handler `0x05`.
- None of the located protocols give it access to `LenovoCryptServiceSmm.efi`'s memory.
- No mechanism for cross-module writes to a fixed `.bss` address in another module exists in standard UEFI without an explicit pointer-passing protocol, and this module installs no such protocol.

Conclusion: the salt is permanently zero in normal operation.

### Cryptographic implication

The construction documented above:

    output = SHA-1( SHA-1(input)[0..7] || salt[0..10] )

reduces with `salt = 0x00 × 10` to:

    output = SHA-1( SHA-1(input)[0..7] || 0x00000000000000000000 )

The round-2 SHA-1 therefore provides:

- **Domain separation** — the round-2 input space is distinct from the round-1 input space, so the two values can be safely used in distinct contexts without collision.
- **No additional entropy** — the salt contributes 0 bits of input variability.
- **No per-machine binding** — the construction is identical on every T430u that runs this firmware version.

For password verification, this means the hash digest stored against a given password is the same on every machine. The per-machine binding (if any) of the SVP subsystem must therefore live elsewhere — most likely in *what the digest is compared against* (e.g., a per-machine secret stored in EC-protected memory, or the comparison taking place inside the EC after a challenge/response), not in the hash construction itself.

### What this opens up

The architectural question now sharpens to: where is the per-machine binding for the SVP password subsystem, if not in the hash?

Three candidates worth investigating:

1. **The 8-byte CMOS region at `0xB0–0xB7`** managed by the `73E47354` protocol in `LenovoCryptServiceSmm.efi`. Used as input to AES key derivation in `LenovoCryptService.efi` per `cryptservice_aes_key_derivation.md`. Possibly a *different* per-machine secret used for AES rather than for password storage.
2. **An EC-stored digest** that the SVP comparison is performed against. The EC's secret region is write-protected from the host, so this would explain the "per-machine binding lives outside the host firmware" pattern. `LenovoSvpManagerSmm.efi` locates the EC mailbox protocol `0DE8BACF` and could be reading a stored digest from it for comparison.
3. **No per-machine binding at all** for the password hash — passwords are hashed identically on every machine, and the only per-machine state is the comparison target. This is plausible for OEM SVP designs of this era.

Resolving which is the case requires reading the rest of `LenovoSvpManagerSmm.efi` (in particular SMI handler `0x05` at RVA `0x520` and the function `FUN_00000a8c` that gates the entry point) and tracing what gets compared against what.
