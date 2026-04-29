# RESOLVED: 6C48F74A is SHA-1

## Conclusion

The hash algorithm GUID `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE` is plain SHA-1.

Implementation lives in `SystemCryptSvcRt.efi` — the Phoenix system crypto
service runtime, 44,512 bytes. The module exposes a service-record table with
one entry per algorithm.

## How we proved it

Three independent lines of evidence:

### 1. The record name is literally "SHA1"

The 88-byte service record at offset `0x320` begins with the UTF-16LE bytes:

    53 00 48 00 41 00 31 00 00 00   = "SHA1\0" in UTF-16LE

### 2. The digest size field matches SHA-1

Each service record contains a 64-bit `digest_size` field at offset `+0x30`.
Across the four hash records:

    Record    Offset  digest_size  Standard SHA-1/SHA-256/etc.
    -----     ------  -----------  ----------------------------
    MD5       0x2c8   16 bytes     ✓ correct
    SHA1      0x320   20 bytes     ✓ correct
    SHA256    0x378   32 bytes     ✓ correct
    SHA512    0x3d0   64 bytes     ✓ correct

### 3. The four SHA-1 round constants are present

Searching the binary for the canonical SHA-1 K constants found them all,
contiguous in memory at 4-byte stride:

    K1 0x5A827999 at 0x1ee0
    K2 0x6ED9EBA1 at 0x1ee4
    K3 0x8F1BBCDC at 0x1ee8
    K4 0xCA62C1D6 at 0x1eec

The SHA-256 K[] table begins immediately after at `0x1ef0`, confirming a
single literal-constant pool packing the hash constants together.

## The algorithm-record table layout

Each hash record is 88 bytes:

    +0x00 (32 bytes)  UTF-16LE name (null-padded)
    +0x20 (8 bytes)   context size
    +0x28 (8 bytes)   block size (0x40 = 64 for MD5/SHA-1/SHA-256)
    +0x30 (8 bytes)   digest size  ← what we used to identify each algorithm
    +0x38 (8 bytes)   pointer to Init function
    +0x40 (8 bytes)   pointer to Update function
    +0x48 (8 bytes)   pointer to Final function
    +0x50 (8 bytes)   pointer into the GUID dispatch table at 0x1c50

The +0x50 GUID pointer is the link between this record table and the 14-GUID
array we identified earlier:

    Algorithm  Record GUID points to  GUID at that address
    ---------  ---------------------  -------------------------------------
    MD5        0x1cc0                 2D6C43DA-2CCE-4298-9BA3-4B56E46433FF
    SHA1       0x1cd0                 6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE  ★
    SHA256     0x1ce0                 991595D2-DE11-41E7-B3DD-759149251761
    SHA512     0x0000 (NULL)          (not exposed via the dispatcher)

## What this means for the T430u password subsystem

With this resolved, the full cryptographic story can finally be named.
Every algorithm and key source has been traced.
