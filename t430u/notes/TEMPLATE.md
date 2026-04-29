# T430u &lt;ModuleName&gt; Analysis

## Module

- **File**: `<ModuleName>.efi` (extracted from the 4MB BIOS dump)
- **Size**: N bytes
- **Type**: PE32+ x86-64, EFI Boot Service Driver / EFI Runtime Driver / SMM driver
- **Role**: One sentence — what this module contributes to the boot or password subsystem.

## Big picture

Two or three paragraphs written after reading the full disassembly, not before. State what the module is for, where it sits in the architecture, and what the most important thing about it is. Don't repeat the bullet points above.

Describe what new questions this module raises that weren't visible from the modules already analyzed. The first paragraph is the punchline; the rest is context.

## Strings

Most UEFI modules carry very few strings. List them all.

| Offset | String |
|--------|--------|
| `0xNNN` | `SomeName` (UTF-16LE) |
| `0xNNN` | `some-ascii-string` (ASCII) |

If a string is an EFI variable name, say so. If it's display text or a diagnostic, say that instead. If the module contains no readable strings, that's worth noting explicitly — it often means the module is pure protocol logic with no user-facing path.

## GUIDs

List every GUID in the data section. For each one: is it installed here, located here (consumed), or just embedded as a parameter passed elsewhere? Note which GUIDs are shared with other modules we've analyzed — shared GUIDs are architectural seams.

| Offset | GUID | Notes |
|--------|------|-------|
| `0xNNN` | `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` | Produced / consumed / parameter — role |

Run `pe_inspect.py --guid-db scripts/guids.txt` first; the known GUIDs will be annotated automatically.

## Function map

A call-tree sketch of every function worth naming. Use `├──` for children, `└──` for last child, `│` for continuation lines. Include the key facts in the annotation: what a function does, not just where it is. Functions too small or too unimportant to name can be grouped as "helpers."

```
<ModuleName>.efi
├── entry(ImageHandle, SystemTable)
│   ├── FUN_XXXXXXXX  ← init: locate prerequisite protocols, stash pointers
│   ├── BS->InstallProtocolInterface(GUID@0xNNN, &table_at_.text:0xNNN)
│   └── BS->RegisterProtocolNotify / SMI handler registration
│
├── FUN_XXXXXXXX  ← the main handler or callback
│   ├── FUN_XXXXXXXX  ← sub-step A
│   └── FUN_XXXXXXXX  ← sub-step B
│
└── helpers:
    FUN_XXXXXXXX  ← ZeroMem
    FUN_XXXXXXXX  ← memcpy
    FUN_XXXXXXXX  ← CMOS read (I/O 0x70/0x71)
```

## [Topic-specific findings — name each section by what it finds]

One section per finding worth writing up in detail. Name sections by the thing they describe ("The key derivation chain", "The SMI dispatch structure", "The CMOS scratchpad role") rather than by the activity ("Tracing FUN_0000289C").

Each finding: state the fact up front in the first sentence. Then explain how you traced it. Then say what it means in the context of the larger architecture. If you made an error in an earlier writeup that this investigation corrects, say so plainly and say what was wrong.

The detail level should match what you'd want to read six months later when you've forgotten the specifics. Show the disassembly fragment that proves the claim; don't just assert.

## What's still uncertain

Be honest. List things you looked at and couldn't trace, guesses you're making and why, and questions this module raises without answering. Mark guesses as guesses.

For example:
- "I believe X because Y, but I haven't located the code that establishes Z."
- "The function at `FUN_XXXXXXXX` is called from the handler but I haven't traced what it does."
- "The GUID at `0xNNN` appears in the data but no code references it — possibly a linker-included header constant."

## Threads to pull next

In rough priority order. Each thread is a concrete action, not a vague direction.

1. **Extract `<NextModule>.efi`** — it's the likely producer of `<GUID>`, which would answer `<specific question>`.
2. **`uefifind` for `<GUID bytes>`** across all modules — would show who else consumes or produces this protocol.
3. **Trace `FUN_XXXXXXXX`** in this module — it's called from the main handler but not yet decoded.

The best threads are the ones that would change the architectural picture: finding the module that implements a known-unknown, or confirming a producer/consumer relationship that's currently inferred.

---

*This is structural reverse engineering of firmware on hardware I own. Nothing here is a bypass path or vulnerability disclosure. The interest is architectural: understanding what the firmware does and why.*
