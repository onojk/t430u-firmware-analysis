# T430u Hash Algorithm Investigation: Where is `6C48F74A` Implemented?

## Conclusion (up front)

**The hash algorithm with GUID `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE` is NOT
implemented in `LenovoCryptService.efi`.**

This module CONSUMES the algorithm GUID — it passes it as a parameter to a generic
hash dispatcher located via two layers of indirection — but does not itself implement
any byte-mixing routine that would correspond to the algorithm.

The algorithm implementation lives somewhere else in the firmware. Tracing it
further requires extracting and analyzing additional modules.

## Two corrections to prior writeups

While doing this trace I discovered two errors in earlier writeups that I want to
flag plainly.

### Correction 1: I had Boot Services offsets wrong

In the prior `cryptservice_smm_analysis.md` (and elsewhere), I labeled
`BS+0x80` as `RegisterProtocolNotify`. **That was wrong.** Per the UEFI 2.x
specification, `BS+0x80` is `InstallProtocolInterface`. The actual
`RegisterProtocolNotify` is at `BS+0xA8`.

Implications for the prior writeup:

- Where I wrote "this module RegisterProtocolNotify on `FE2965BB-...`," it actually
  **InstallProtocolInterface** on the GUID at the location I cited. This means the
  module *publishes* (rather than waits for) certain protocols.
- Specific impact on this DXE module: the call at `entry+0x30` is in fact
  installing protocol GUID `73E47354-B0C5-4E00-A714-9D0D5A4FDBFD` with a function
  table located at `.text:0x240`. That's significant new information — see "What
  this module DOES install" below.

I'll re-verify the SMM peer's calls in a follow-up. The structural conclusions of
those writeups are mostly intact; the protocol-identification labeling was off.

### Correction 2: This module does not publish stage-1 or stage-2 hash protocols

In `cryptservice_dxe_analysis.md` I "corrected" my SMM-peer writeup by saying that
this DXE module also publishes the stage-1 (`E3ABB023-...`) and stage-2
(`E01FC710-...`) hash protocol GUIDs. The argument was that those GUIDs' bytes
appear in the data section at offsets `0x470` and `0x450`.

**The bytes are there, but they are never referenced by any code in this module.**
A scan for `LEA reg, [RIP+disp32]` instructions targeting addresses in the
`0x44E..0x471` range turns up zero hits. The GUIDs are inert data — likely embedded
because the developer included a shared header that declared them, but unused at
runtime.

So the original writeup was correct: **only the SMM peer publishes stage-1 and
stage-2.** My correction was wrong. Correcting the correction.

## What this module DOES install

Re-reading the `entry()` function with the correct BS offset:

```
entry(ImageHandle, SystemTable):
  CALL FUN_00003140       ; saves ST, BS, RT pointers to globals
  CALL FUN_0000289C       ; populates DAT_00004B00, DAT_00004B10
                          ; (the AES keys we identified previously)
  
  CALL [BS + 0x80]        ; InstallProtocolInterface
                          ;   Handle:    &local
                          ;   Protocol:  &GUID@0x410 = 73E47354-B0C5-4E00-A714-9D0D5A4FDBFD
                          ;   Type:      0 (EFI_NATIVE_INTERFACE)
                          ;   Interface: &table_at_.text:0x240
  
  CALL FUN_000030FC       ; CreateEventEx (BS+0x170) for some event group
```

So this module's contribution to the system is one protocol installation:

```
GUID 73E47354-B0C5-4E00-A714-9D0D5A4FDBFD
  └── interface: a 4-method function-pointer table at .text:0x240
        ├── slot 0 (.text:0x240 → 0x2994): hash service caller
        ├── slot 1 (.text:0x248 → 0x2B80): AES-CBC encrypt with derived key
        ├── slot 2 (.text:0x250 → 0x2DC4): AES-CBC decrypt (likely; not yet traced)
        └── slot 3 (.text:0x258 → 0x3008): second hash variant
```

That GUID (`73E47354-...`) is one of the four "shared but unidentified" GUIDs from
the SVP investigation. Now identified: **it's the LenovoCryptoService DXE protocol**,
the protocol that the password subsystem talks to when it wants either a hash or an
AES operation.

## What this module CONSUMES

The full list of protocols `LenovoCryptService.efi` looks up via `LocateProtocol`:

| GUID | Where used | Role |
|---|---|---|
| `D0B3D668-16CF-4FEB-95F5-1CA3693CFE56` | `FUN_00002994`, `FUN_00003008` | The "hash service" container |
| `69188A5F-6BBD-46C7-9C16-55F194BEFCDF` | `FUN_00002994`, `FUN_00003008` | The hash dispatcher |
| `DBFF9D55-89B7-46DA-BDDF-677D3DC0241D` | `FUN_000028C4` | A named-service registry |
| `82B244DC-8503-454B-A96A-D0D2E00BF86A` | `FUN_00002760`, `FUN_00002838` | SVP storage protocol |
| `5B1B31A1-9562-11D2-8E3F-00A0C969723B` | (init flow) | Standard EFI Loaded Image |

And the GUIDs the module uses as **parameters** (i.e., passes by reference but
doesn't locate as a protocol):

| GUID | Where | Role |
|---|---|---|
| `6C48F74A-B4DF-461F-80C4-5CAE8A85B7EE` | data offset `0x330` | Hash algorithm identifier |
| `15E896BE-0CDF-47E2-9B97-A28A398BC765` | data offset `0x270` | Service name within DBFF9D55 registry |
| `C5A3095A-87F7-4AF8-B393-09CC4AF08739` | data offset `0x300` | Different algorithm? Used by FUN_3008 |
| `C0206BF0-6D0A-4988-B7E0-BF2FEB6D747D` | data offset `0x310` | Related to the C5A3095A path |

The literal byte-string for `6C48F74A` appears **exactly once** in this module — at
data offset `0x330`. It's referenced from code only at `.text:0x2A4F`, where a
pointer to it is stored into a hash-service context. That's the one and only
reference.

## How the hash actually gets done

Walking through `FUN_00002994` with corrected understanding:

```
FUN_00002994(input, length, key/aux, output):
  
  # Step A: Find the hash service
  LocateProtocol(GUID D0B3D668) → service_proto_handle    [stored in local_50]
  LocateProtocol(GUID 69188A5F) → dispatcher_proto_handle [stored in local_30]
  
  ctx = FUN_00002994_helper(...)   # via FUN_000028C4
  # FUN_000028C4 enumerates a registry (DBFF9D55) looking for service "15E896BE"
  # When found, it returns a function-pointer (8 bytes from offset 0x3A of the entry)
  
  # Step B: build context and invoke service 4 times
  ctx[0x10] = 0x28
  ctx[0x18] = 0           # operation type
  ctx[0x28] = dispatcher  # the 69188A5F handle  
  ctx[0x30] = &GUID@0x330 # the algorithm identifier (6C48F74A)
  ctx[0x38] = output buffer
  
  service_proto[0](ctx)   # call 1 — initialize hash session
  
  ctx[0x18] = 3           # op = 3 (Update)
  ctx[0x10] = 0x30
  ctx[0x30] = output_buf  # ?
  ctx[0x38] = input
  ctx[0x40] = length
  service_proto[0](ctx)   # call 2 — push input bytes
  
  ctx[0x18] = 4           # op = 4 (Update with key data?)
  ctx[0x10] = 0x38
  ctx[0x40] = key_aux     
  ctx[0x48] = some buffer
  service_proto[0](ctx)   # call 3 — push key/aux bytes
  
  ctx[0x18] = 2           # op = 2 (Final)
  ctx[0x10] = 0x20
  service_proto[0](ctx)   # call 4 — finalize, produces digest
  
  CopyMem(caller_output, digest, length)
  FreePool(ctx)
  return 0
```

The actual hash math happens inside whatever module implements `service_proto[0]`,
which is the function at offset `0x3A` of a registry entry named `15E896BE-...`
within the `DBFF9D55-...` registry. **That module is not this one.**

## Why the hash algorithm GUID is metadata, not code

The dispatcher protocol pattern means: the implementation module registers itself
once, advertising "I know how to do algorithm 6C48F74A," and from then on, callers
who want that algorithm pass its GUID as a parameter rather than looking up a
specific protocol per algorithm. This is exactly the same design as the standard
`EFI_HASH2_PROTOCOL` in UEFI 2.5+, where you call `Hash2(self, AlgorithmGuid, ...)`
and the same protocol can do SHA-256, SHA-384, or SHA-512 depending on the GUID.

The Lenovo design uses three Lenovo-proprietary GUIDs to play these roles:

```
DBFF9D55-...    = the SERVICE REGISTRY (analogous to a service-locator)
   └── 15E896BE-...  = the NAME of the hash service within that registry
69188A5F-...    = the DISPATCHER protocol (handles the multi-call protocol)
   └── 6C48F74A-...  = the ALGORITHM IDENTIFIER ("which hash do I want?")
D0B3D668-...    = a SECOND service interface (purpose unclear; collaborates with above)
```

This is consistent with a layered, multi-team firmware architecture. The hash math
team owns the implementation module; the password team writes against the abstract
algorithm-by-GUID interface; nobody has to recompile anyone else's code to swap
algorithms.

## Where the implementation likely lives

The module that implements `6C48F74A-...` must:

1. Install protocol `D0B3D668-...` (the hash service)
2. Install or register-with `DBFF9D55-...` (the service registry) using name
   `15E896BE-...`
3. Install or implement `69188A5F-...` (the hash dispatcher)
4. Have substantial code (the actual hash function — SHA-256 alone is ~3 KB,
   SHA-1 ~2 KB, SHA-512 ~5 KB)

Phoenix-based firmware on this generation of ThinkPad typically has modules with
names like:
- `PhoenixHashServices`
- `LenovoCryptoCore` 
- `SecureCore`
- `HashLibPei`/`HashLibDxe`

Without extracting and grep'ing for the GUID bytes across all unextracted modules,
I can't name the specific file. The user's `uefiextract` already extracted all
modules from the BIOS image; the module containing this implementation is sitting
somewhere in `~/byte-evolution-tracker/t430u/extracted/t430u_4mb_spi_backup.rom.dump/`.

## Concrete next step

The cleanest way to find the implementation:

```bash
# From the user's machine:
cd ~/byte-evolution-tracker/t430u/extracted/

# Search every PE32 body for the literal bytes of 6C48F74A
# (LE byte order: 4a f7 48 6c df b4 1f 46 80 c4 5c ae 8a 85 b7 ee)
find . -name 'body.bin' -exec sh -c '
  if xxd -p "$1" | tr -d "\n" | grep -q "4af7486cdfb41f4680c45cae8a85b7ee"; then
    echo "HIT: $1"
  fi
' _ {} \;
```

That should produce a list of every module containing the algorithm GUID. We
already know two will be in the list (`LenovoCryptService.efi` and
`LenovoCryptServiceSmm.efi`). A third hit would be the implementation we want.

Doing the same for `D0B3D668` (LE: `68 d6 b3 d0 cf 16 eb 4f 95 f5 1c a3 69 3c fe 56`)
and looking for occurrences NOT in the two modules we've already analyzed would
also pinpoint the implementer.

## Honest admission

This pass through the listing did not find the algorithm. What it did do:

1. Confirmed (via byte-search and XREF analysis) that the algorithm is not
   implemented in this module.
2. Identified what this module DOES install: protocol `73E47354-...` with a
   four-method interface combining hash and AES services.
3. Discovered that previous writeups had Boot Services offsets wrong, and that
   one "correction" I made earlier was itself wrong.
4. Mapped the layered-service architecture (registry → service-by-name →
   dispatcher → algorithm-by-GUID) so the next investigation knows what to look for.

The actual byte-mixing math remains unfound in this module. Finding it requires
extracting more modules, which is a discrete next step.

## Updated module status

| Module | Role | Status |
|---|---|---|
| `LenovoPasswordCp.efi` | Password input pipeline | Analyzed |
| `LenovoSvpManagerDxe.efi` | A/B SVP block, error display | Analyzed |
| `LenovoSvpManagerSmm.efi` | SVP cache, lockout, EC client | Analyzed |
| `LenovoCryptServiceSmm.efi` | Stage-1/2 hash protocols (SMM side) | Analyzed (with offset error noted above) |
| `LenovoCryptService.efi` | LenovoCryptoService (DXE side, AES + key derivation) | Analyzed |
| `LenovoWmaPolicyDxe.efi` | Wireless whitelist | Analyzed |
| **TBD: hash algorithm implementer** | Implements `6C48F74A`, registers `D0B3D668`/`69188A5F`/`DBFF9D55` | **Not yet located** |
| `LenovoMailBoxSmm.efi` | EC mailbox protocol producer | Not yet extracted |
| `LenovoSetupSecurityDxe.efi` | Security setup screen | Not yet extracted |
| `LenovoHpmDxe.efi` | HDD password manager | Not yet extracted |
