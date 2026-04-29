# T430u Firmware Analysis

Reverse engineering notes for the Lenovo ThinkPad T430u BIOS, focused on
understanding the password-handling subsystem on hardware I own.

## Scope

This is structural analysis for personal comprehension of firmware on a
machine I own. Nothing here is a vulnerability disclosure or bypass path.

## Repository layout

```
t430u/
├── notes/      Markdown writeups, one per analyzed module
├── scripts/    Helper scripts (e.g. extract_module.sh)
├── dumps/      ROM dumps (gitignored — sensitive per-machine data)
├── extracted/  UEFITool output (gitignored — regenerable)
└── ghidra-projects/  Ghidra workspace (gitignored — regenerable)
```

## Modules analyzed

See `t430u/notes/` for the full set of writeups. Highlights:

- `wireless_whitelist.md` — 30-entry WiFi allowlist
- `password_cp_analysis.md` — keystroke pipeline
- `svp_manager_*.md` — Supervisor Password A/B storage
- `cryptservice_*.md` — Lenovo crypto wrappers (AES-CBC engine)
- `cryptservice_aes_key_derivation.md` — per-machine AES key from EC
- `hash_algorithm_resolved.md` — final answer: SHA-1, AES-128-CBC

## Tools

- UEFITool / `uefiextract` for module extraction
- Ghidra for disassembly
- Standard hex/strings/python for byte-pattern analysis
