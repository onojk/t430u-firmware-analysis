# T430u CryptServiceSmm — Handler 0x83 Internals

## What this document adds

This is a detailed follow-on to `cryptservice_smm_analysis.md`, adding a full trace of
`FUN_00000560` (SMI command 0x83 — the stage-1 hash handler). With this trace, the
exact input/output contract of the stage-1 hash protocol is now named.

## Headline finding

**The stage-1 hash protocol is not a single SMI call — it is a chunked eight-call
protocol.** The caller must invoke SMI 0x83 eight times, delivering 8 bytes per call,
to push all 64 bytes of the password buffer into the handler. On the eighth call the
handler computes SHA-1 over the assembled 64-byte buffer, truncates to 7 bytes, appends
10 bytes of a CMOS-derived salt (from the `DAT_00000E18` global), and runs a second hash
over those 17 bytes. Eight bytes of the second hash are returned to the caller via the
SMI communication buffer.

The stage-1 hash is therefore:

```
stage1_hash(password_buf_64):
    d  = SHA-1(password_buf_64)         # 20-byte digest
    s  = d[0..7] || DAT_E18[0..10]      # 7 + 10 = 17 bytes
    h  = HashService(s)                 # algorithm 6C48F74A = SHA-1
    return h[0..8]                      # 8 bytes to caller
```

## The SMI communication protocol for handler 0x83

The SMM communication buffer layout, as decoded from the handler:

| Offset | Field | Direction | Notes |
|--------|-------|-----------|-------|
| `+0x00` | status | out | 0 = success, `0x80000000` = error |
| `+0x04` | data_lo (4 bytes) | in/out | input bytes on chunk calls; hash output (lo) on final |
| `+0x08` | data_hi (4 bytes) | in/out | input bytes on chunk calls; hash output (hi) on final |
| `+0x10` | chunk_idx | in/out | 0 = first chunk (INIT path); 1..7 = continuation; echoed 0 on return |

Each call delivers 8 bytes of password data (4 bytes in `+0x04`, 4 bytes in `+0x08`).
The handler tracks how many chunks have arrived via an internal counter at `DAT_00000DC8`.

## The chunking and finalization logic

```c
// Pseudocode for FUN_00000560 (handler 0x83)

if (smi_buf->field_10 == 0) {
    // INIT path: caller passing 0 to start a new operation
    memset(&DAT_dd0, 0, 0x41);          // zero 65 bytes of state buffer
    memset(&local_40, 0, 0x21);         // zero 33 bytes on stack
    DAT_dc8 &= 0;                       // counter = 0
    goto continue_to_chunk_path;
}

// CONTINUE / FINALIZE path: caller passing chunk_index in field_10
chunk_idx = smi_buf->field_10;
if (chunk_idx >= 8) goto error_0x80000000;        // bounds check
if (chunk_idx != DAT_dc8) goto error_0x80000000;  // must match expected counter

continue_to_chunk_path:
    offset = chunk_idx * 8;             // 8 bytes per chunk
    memcpy(state + offset,     &smi_buf->field_4, 4);    // low word
    memcpy(state + offset + 4, &smi_buf->field_8, 4);    // high word

    DAT_dc8 += 1;                       // bump counter
    if (DAT_dc8 != 8) {
        // Not the last chunk — return success, wait for next chunk
        smi_buf->field_0  = 0;
        smi_buf->field_10 = 0;
        return;
    }

    // FINAL chunk just landed — we now have 64 bytes in state.
    SHA-1(state, 0x40, &local_40);          // 20-byte digest → local_40

    memset(&local_68, 0, 0x20);
    memcpy(&local_68, &local_40, 7);        // first 7 bytes of SHA-1 digest

    // FUN_000009e4: append DAT_e18[0..10], run hash, write result to local_68
    int err = FUN_000009e4(&local_68);
    if (err == 0x80000000) {
        smi_buf->field_0 = 0x80000000;
        return;
    }

    memcpy(&smi_buf->field_4, &local_68,       4);  // result bytes 0..3
    memcpy(&smi_buf->field_8, &local_68 + 0x4, 4);  // result bytes 4..7

    DAT_dc8       = 0;   // reset counter
    smi_buf->field_0  = 0;
    smi_buf->field_10 = 0;
    return;
```

## The salt composition step — FUN_000009e4

`FUN_000009e4` is shared between handler 0x83 and handler 0x90. It does:

1. Allocate two stack buffers: `buf1[0x11]` (17 bytes) and `out[0x20]` (32 bytes), both zeroed.
2. `memcpy(buf1, caller_input, 7)` — copies the 7-byte SHA-1 prefix from the caller.
3. `memcpy(buf1+7, &DAT_00000E18, 10)` — appends 10 bytes of the CMOS scratchpad salt.
4. `FUN_00000930(buf1, 0x11, ..., out)` — invokes the hash dispatcher with the 17-byte
   concatenation, producing up to 32 bytes in `out`.
5. `memcpy(caller_dest, out, 0x20)` — returns the full output to the caller.

`FUN_00000930` is the dispatcher that routes through the `69188A5F-...` hash protocol
to the `6C48F74A-...` algorithm — which we have independently confirmed is SHA-1
(see `hash_algorithm_resolved.md`). So the second hash is also SHA-1.

## What DAT_00000E18 is

`DAT_00000E18` is a 10-byte buffer in the module's `.data` section. Based on the
module-level analysis, the most likely source is CMOS-derived state, initialized during
or after the module's `FUN_00000A80` call (which reads CMOS offsets B0..B7). A 2-byte
extension is possible if the module reads two additional OEM CMOS bytes alongside B0..B7.

This datum has not been fully traced — see "What's still uncertain" below.

## The two-SHA-1 construction

With `hash_algorithm_resolved.md` confirming that `6C48F74A-...` is plain SHA-1, the
full stage-1 computation can now be written out without unknowns:

```
stage1(pw64):
    d = SHA-1(pw64)                         # standard FIPS 180-4, input = 64 bytes
    s = d[0..6] ++ CMOS_salt[0..9]          # 7 bytes of digest, 10 bytes of salt
    return SHA-1(s)[0..7]                   # first 8 bytes of SHA-1(17-byte input)
```

The caller gets back 8 bytes. Whether stage-1 results in a 16-byte digest (as suggested
by PasswordCp's buffer sizes) would require either two sequential invocations of 0x83,
or a different interpretation of the output length. This is still an open question.

## Relationship to command 0x90

Handler 0x90 (`LAB_00000800`) calls the same `FUN_000009e4` but does not assemble a
64-byte buffer first. It appears to invoke the salted hash directly over a shorter
caller-supplied input. The three handlers thus share a common "keyed SHA-1" primitive
(`FUN_000009e4`) but differ in what they hand to it:

- **0x83** (stage-1 hash): SHA-1(64-byte password buffer), then feed 7 bytes into FUN_9e4
- **0x8F** (stage-2 hash): same shape as 0x83 but different argument layout (not yet fully traced)
- **0x90** (keyed hash): feed caller-supplied bytes directly into FUN_9e4

## What the stage-2 handler (0x8F) adds

`FUN_000006A8` (command 0x8F) has nearly the same structure as `FUN_00000560`. The
main visible difference is the size parameter to `FUN_000009e4` — it may take the 8-byte
output from stage-1 as its input rather than rebuilding the 64-byte accumulation. Full
trace of 0x8F is deferred.

## What's still uncertain

1. **What is `DAT_00000E18`?** The 10-byte salt used by `FUN_000009e4` is a machine-specific
   constant but its initialization path has not been fully traced. Best guess: derived from
   CMOS OEM bytes, like the 8-byte CMOS state at `DAT_00000E68` — but 2 bytes longer, which
   is unexplained.

2. **Does the caller invoke 0x83 twice to get a 16-byte result?** `PasswordCp` uses 16-byte
   output buffers throughout. If handler 0x83 returns only 8 bytes per invocation, the caller
   would need to call it twice. Tracing the `PasswordCp` → `E3ABB023-...` call site would
   resolve this.

3. **Full trace of handler 0x8F (stage-2).** The stage-2 handler is the transformation
   applied on top of the stage-1 output. Understanding it would complete the full
   password-to-stored-value pipeline.

4. **The exact source for `DAT_00000E18`.** If it turns out to be EC-derived rather than
   CMOS-derived, the salt is per-machine in a stronger sense (EC is write-protected from
   non-SMM code), making offline dictionary attacks require the EC dump.

## Architecture update

```
User password (typed by user)
       │
       │ → LenovoPasswordCp: validate charset, build 64-byte buffer
       │
SMI 0x83 ×8 (one call per 8-byte chunk)
       │
       │  FUN_00000560 assembles 64 bytes →
       │    SHA-1(64 bytes) = 20-byte digest →
       │    d[0..7] ++ DAT_E18[0..10] = 17-byte salted input →
       │    SHA-1(17 bytes)[0..8] = 8-byte stage-1 output
       │
SMI 0x8F (stage-2, takes stage-1 output)
       │
       │  FUN_000006A8 (not yet fully traced)
       │
       │ → 16-byte final password hash
       │
LenovoSvpManagerDxe → LenovoSvpManagerSmm → EC EEPROM (compare & gate)
```
