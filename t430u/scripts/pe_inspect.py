#!/usr/bin/env python3
"""
pe_inspect.py — zero-dependency PE32+ triage for UEFI modules.

Output is markdown formatted for dropping into a notes/<module>.md writeup.

Usage:
    pe_inspect.py <binary.efi> [--guid-db guids.txt] [--output out.md]
"""

import sys
import struct
import argparse
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────────────────

MACHINE_NAMES = {
    0x8664: 'x86-64 (AMD64)',
    0x014C: 'x86 (i386)',
    0xAA64: 'ARM64 (AArch64)',
}

SUBSYSTEM_NAMES = {
    0x00: 'Unknown',
    0x01: 'Native',
    0x02: 'Windows GUI',
    0x03: 'Windows CUI',
    0x09: 'Windows CE',
    0x0A: 'EFI Application',
    0x0B: 'EFI Boot Service Driver',
    0x0C: 'EFI Runtime Driver',
    0x0D: 'EFI ROM Image',
    0x0E: 'Xbox',
}

IMAGE_SCN_CNT_CODE            = 0x00000020   # section contains executable code
IMAGE_SCN_CNT_INITIALIZED_DATA= 0x00000040   # section contains initialized data
IMAGE_SCN_MEM_DISCARDABLE     = 0x02000000   # section can be discarded (.reloc, etc.)
IMAGE_SCN_MEM_EXECUTE         = 0x20000000   # section is executable (memory flag)


# ── PE parsing ───────────────────────────────────────────────────────────────

def parse_pe(data: bytes) -> dict:
    """
    Parse a PE32+ binary and return header fields + section table.

    PE32+ Optional Header layout (offsets from opt_start):
      0   Magic              WORD   (0x020B for PE32+)
      2   MajorLinkerVer     BYTE
      3   MinorLinkerVer     BYTE
      4   SizeOfCode         DWORD
      8   SizeOfInitData     DWORD
     12   SizeOfUninitData   DWORD
     16   AddressOfEntryPt   DWORD
     20   BaseOfCode         DWORD
     24   ImageBase          QWORD  ← PE32+ specific (was DWORD in PE32)
     32   SectionAlignment   DWORD
     36   FileAlignment      DWORD
     40   MajorOSVersion     WORD
     42   MinorOSVersion     WORD
     44   MajorImageVersion  WORD
     46   MinorImageVersion  WORD
     48   MajorSubsysVer     WORD
     50   MinorSubsysVer     WORD
     52   Win32VersionValue  DWORD
     56   SizeOfImage        DWORD
     60   SizeOfHeaders      DWORD
     64   CheckSum           DWORD
     68   Subsystem          WORD
     70   DllCharacteristics WORD
     72   SizeOfStackRsv     QWORD
     80   SizeOfStackCom     QWORD
     88   SizeOfHeapRsv      QWORD
     96   SizeOfHeapCom      QWORD
    104   LoaderFlags        DWORD
    108   NumberOfRvaAndSzs  DWORD
    112   DataDirectory[]
    """
    if len(data) < 64:
        raise ValueError("file too small for a PE header")
    if data[:2] != b'MZ':
        raise ValueError("missing MZ signature")

    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_off + 4 > len(data) or data[pe_off:pe_off + 4] != b'PE\x00\x00':
        raise ValueError("PE signature not found at e_lfanew offset")

    coff = pe_off + 4  # COFF File Header
    (machine, num_sections, timestamp, _sym_ptr, _num_syms,
     opt_size, characteristics) = struct.unpack_from('<HHIIIHH', data, coff)

    opt = coff + 20  # Optional Header
    if opt + 2 > len(data):
        raise ValueError("optional header missing")
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic != 0x020B:
        raise ValueError(
            f"not PE32+ (Optional Header Magic = {magic:#06x}; expected 0x020b)")

    entry_rva  = struct.unpack_from('<I', data, opt + 16)[0]
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    size_image = struct.unpack_from('<I', data, opt + 56)[0]
    subsystem  = struct.unpack_from('<H', data, opt + 68)[0]

    sections = []
    sec_tbl = opt + opt_size
    for i in range(num_sections):
        base = sec_tbl + i * 40
        if base + 40 > len(data):
            break
        name = data[base:base + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, base + 8)
        sec_chars = struct.unpack_from('<I', data, base + 36)[0]
        sections.append(dict(
            name=name,
            vaddr=vaddr,
            vsize=vsize,
            raw_ptr=raw_ptr,
            raw_size=raw_size,
            characteristics=sec_chars,
        ))

    return dict(
        machine=machine,
        file_characteristics=characteristics,
        entry_rva=entry_rva,
        image_base=image_base,
        size_of_image=size_image,
        subsystem=subsystem,
        sections=sections,
        file_size=len(data),
    )


# ── Section helpers ──────────────────────────────────────────────────────────

def is_code_section(sec: dict) -> bool:
    """True if section has the CNT_CODE flag (0x20). Name-independent."""
    return bool(sec['characteristics'] & IMAGE_SCN_CNT_CODE)


def section_for_rva(sections: list, rva: int):
    for s in sections:
        top = s['vaddr'] + max(s['vsize'], s['raw_size'])
        if s['vaddr'] <= rva < top:
            return s
    return None


# ── GUID detection ───────────────────────────────────────────────────────────

def fmt_guid(raw16: bytes) -> str:
    """Format 16 bytes as uppercase GUID string."""
    d1, d2, d3 = struct.unpack_from('<IHH', raw16, 0)
    b = raw16[8:16]
    return (f"{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{b[0]:02X}{b[1]:02X}-"
            f"{b[2]:02X}{b[3]:02X}{b[4]:02X}{b[5]:02X}{b[6]:02X}{b[7]:02X}")


def plausible_guid(raw16: bytes) -> bool:
    """
    Heuristic filter for GUID candidates:
    - Reject all-zero and all-FF
    - Reject sequences with <= 2 unique byte values (compressed/filled regions)
    - Reject if > 10 of 16 bytes are printable ASCII (likely a string, not a GUID)
    """
    if all(b == 0x00 for b in raw16):
        return False
    if all(b == 0xFF for b in raw16):
        return False
    if len(set(raw16)) <= 2:
        return False
    printable = sum(0x20 <= b <= 0x7E for b in raw16)
    if printable > 10:
        return False
    return True


def scan_guids(data: bytes, sections: list, guid_db: dict) -> list:
    """
    Scan all sections with on-disk data at 16-byte stride for plausible GUIDs.
    Skips only DISCARDABLE sections (.reloc etc.) and sections with no raw data.
    No code/data flag restriction: MSVC/EDK2 puts const data (GUIDs, function
    pointer tables) at the beginning of the code section, so filtering on
    CNT_INITIALIZED_DATA would miss every GUID in such binaries.
    Returns list of dicts: guid, section, sec_off, rva, annotation.
    """
    results = []
    for sec in sections:
        if sec['raw_size'] == 0:
            continue
        if sec['characteristics'] & IMAGE_SCN_MEM_DISCARDABLE:
            continue
        raw_end = min(sec['raw_ptr'] + sec['raw_size'], len(data))
        for off in range(sec['raw_ptr'], raw_end - 15, 16):
            raw = data[off:off + 16]
            if not plausible_guid(raw):
                continue
            g = fmt_guid(raw)
            sec_off = off - sec['raw_ptr']
            rva = sec['vaddr'] + sec_off
            annotation = guid_db.get(g.upper(), '')
            results.append(dict(
                guid=g,
                section=sec['name'],
                sec_off=sec_off,
                rva=rva,
                annotation=annotation,
            ))
    return results


# ── String extraction ────────────────────────────────────────────────────────

def scan_strings(data: bytes, sections: list,
                 ascii_min: int = 6, utf16_min: int = 4,
                 ascii_cap: int = 200) -> tuple:
    """
    Scan sections for printable strings.

    ASCII: skips sections with CNT_CODE (0x20). AES T-tables, S-boxes, and
           x86-64 machine code all contain dense runs of printable bytes that
           would otherwise produce hundreds of false positives.
    UTF-16LE: skips only DISCARDABLE sections (.reloc etc.). Code sections
              rarely produce spurious UTF-16 runs, so scanning them is fine.

    Returns (ascii_list, utf16_list), each a list of dicts:
        section, sec_off, rva, string
    ASCII output is capped at ascii_cap entries per section.
    """
    ascii_all = []
    utf16_all = []

    for sec in sections:
        if sec['raw_size'] == 0:
            continue
        sec_chars = sec['characteristics']
        raw_start = sec['raw_ptr']
        raw_end = min(raw_start + sec['raw_size'], len(data))
        if raw_end <= raw_start:
            continue
        seg = data[raw_start:raw_end]

        # --- ASCII strings (data sections only) ---
        if not (sec_chars & IMAGE_SCN_CNT_CODE):
            sec_ascii = []
            truncated = False
            i = 0
            while i < len(seg):
                j = i
                while j < len(seg) and 0x20 <= seg[j] <= 0x7E:
                    j += 1
                if j - i >= ascii_min:
                    s = seg[i:j].decode('ascii', errors='replace')
                    sec_ascii.append(dict(
                        section=sec['name'],
                        sec_off=i,
                        rva=sec['vaddr'] + i,
                        string=s,
                    ))
                    if len(sec_ascii) >= ascii_cap:
                        truncated = True
                        break
                i = j + 1

            if truncated:
                sec_ascii.append(dict(
                    section=sec['name'], sec_off=-1, rva=-1,
                    string=f'[truncated at {ascii_cap} entries]',
                ))
            ascii_all.extend(sec_ascii)

        # --- UTF-16LE strings (all sections except discardable) ---
        if sec_chars & IMAGE_SCN_MEM_DISCARDABLE:
            continue
        i = 0
        while i + 1 < len(seg):
            lo, hi = seg[i], seg[i + 1]
            if 0x20 <= lo <= 0x7E and hi == 0x00:
                j = i
                wchars = []
                while (j + 1 < len(seg) and
                       0x20 <= seg[j] <= 0x7E and seg[j + 1] == 0x00):
                    wchars.append(chr(seg[j]))
                    j += 2
                if len(wchars) >= utf16_min:
                    utf16_all.append(dict(
                        section=sec['name'],
                        sec_off=i,
                        rva=sec['vaddr'] + i,
                        string=''.join(wchars),
                    ))
                    i = j + 2  # step past trailing null word
                    continue
            i += 2

    return ascii_all, utf16_all


# ── Pointer table detection ──────────────────────────────────────────────────

def scan_pointer_tables(data: bytes, sections: list, image_base: int) -> list:
    """
    Find 8-byte aligned runs of >= 3 consecutive QWORDs whose values point into
    the code section(s), either as absolute VAs (image_base + text_rva) or as
    plain RVAs. This catches function-pointer dispatch tables that Ghidra may
    miss when functions are only reachable through indirection.

    Returns list of dicts: section, sec_off, rva, entries
    where entries is a list of (file_off, raw_val, target_rva).
    """
    # Collect .text RVA ranges
    text_ranges = []
    for s in sections:
        if is_code_section(s) and s['vsize'] > 0:
            text_ranges.append((s['vaddr'], s['vaddr'] + s['vsize']))

    if not text_ranges:
        return []

    def as_text_rva(val: int):
        """Return RVA if val points into .text (as RVA or absolute VA), else None."""
        for lo, hi in text_ranges:
            if lo <= val < hi:
                return val  # already an RVA
            if image_base > 0 and (image_base + lo) <= val < (image_base + hi):
                return val - image_base  # absolute → RVA
        return None

    runs = []
    for sec in sections:
        if sec['raw_size'] == 0:
            continue
        if sec['characteristics'] & IMAGE_SCN_MEM_DISCARDABLE:
            continue
        raw_start = sec['raw_ptr']
        raw_end = min(raw_start + sec['raw_size'], len(data))

        # Align starting file offset so that the corresponding VMA is 8-byte aligned.
        # VMA(pos) = image_base + sec['vaddr'] + (pos - raw_start)
        # Alignment requirement on (sec['vaddr'] + pos - raw_start) mod 8 == 0
        vma_base_mod = (sec['vaddr'] - sec['raw_ptr']) % 8
        align_adj = (vma_base_mod - (raw_start % 8)) % 8
        pos = raw_start + align_adj

        run = []  # [(file_off, raw_val, target_rva), ...]
        while pos + 8 <= raw_end:
            val = struct.unpack_from('<Q', data, pos)[0]
            trva = as_text_rva(val)
            if trva is not None:
                run.append((pos, val, trva))
            else:
                if len(run) >= 3:
                    r0_off = run[0][0]
                    runs.append(dict(
                        section=sec['name'],
                        sec_off=r0_off - raw_start,
                        rva=sec['vaddr'] + (r0_off - raw_start),
                        entries=list(run),
                    ))
                run = []
            pos += 8

        if len(run) >= 3:
            r0_off = run[0][0]
            runs.append(dict(
                section=sec['name'],
                sec_off=r0_off - raw_start,
                rva=sec['vaddr'] + (r0_off - raw_start),
                entries=list(run),
            ))

    return runs


# ── LEA RIP-relative xref scanner ───────────────────────────────────────────

def scan_lea_xrefs(data: bytes, sections: list) -> dict:
    """
    Detect `48 8D /r` and `4C 8D /r` instructions with RIP-relative addressing
    (ModRM Mod=00, R/M=101, i.e. ModRM & 0xC7 == 0x05) in code sections.
    This is the dominant x86-64 MSVC/EDK2 pattern for referencing static data.

    Only reports xrefs whose target falls in a non-code (data) section.
    Returns dict: {target_rva: [(src_rva, dsec_name, dsec_off), ...]}
    Grouped by target so callers can see "GUID at .data+0x340 referenced from N sites".

    False-positive rate is non-trivial in dense code; treat output as leads.
    """
    # No code/data flag restriction: MSVC/EDK2 embeds const data (GUIDs,
    # function pointer tables) at the start of the code section, so LEA
    # instructions inside .text point back into .text as their targets.
    # Only discard DISCARDABLE sections (.reloc) and sections with no raw data.
    data_secs = [s for s in sections
                 if s['raw_size'] > 0
                 and not (s['characteristics'] & IMAGE_SCN_MEM_DISCARDABLE)]

    def find_data_sec(rva: int):
        for s in data_secs:
            top = s['vaddr'] + max(s['vsize'], s['raw_size'])
            if s['vaddr'] <= rva < top:
                return s, rva - s['vaddr']
        return None, None

    xrefs = {}  # target_rva → [(src_rva, dsec_name, dsec_off)]

    for sec in sections:
        if not is_code_section(sec) or sec['raw_size'] == 0:
            continue
        raw_start = sec['raw_ptr']
        raw_end = min(raw_start + sec['raw_size'], len(data))
        seg = data[raw_start:raw_end]
        n = len(seg)

        for i in range(n - 6):
            b0 = seg[i]
            if b0 not in (0x48, 0x4C):
                continue
            if seg[i + 1] != 0x8D:
                continue
            modrm = seg[i + 2]
            # RIP-relative: Mod=00, R/M=101 → (modrm & 0xC7) == 0x05
            # Covers all 8 destination registers: {05,0D,15,1D,25,2D,35,3D}
            if (modrm & 0xC7) != 0x05:
                continue

            # 7-byte instruction: REX(1) 8D(1) ModRM(1) disp32(4)
            disp = struct.unpack_from('<i', seg, i + 3)[0]  # signed 32-bit
            src_rva = sec['vaddr'] + i
            next_rva = src_rva + 7
            target_rva = next_rva + disp  # Python int: no overflow concern

            dsec, dsec_off = find_data_sec(target_rva)
            if dsec is None:
                continue

            if target_rva not in xrefs:
                xrefs[target_rva] = []
            xrefs[target_rva].append((src_rva, dsec['name'], dsec_off))

    return xrefs


# ── GUID database ────────────────────────────────────────────────────────────

def load_guid_db(path) -> dict:
    """
    Load a GUID annotation file. Format: one entry per line,
    "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX  description text"
    Lines starting with # are comments.
    Returns dict mapping uppercase GUID string → description.
    """
    db = {}
    if not path:
        return db
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    key = parts[0].upper()
                    val = parts[1] if len(parts) > 1 else ''
                    db[key] = val
    except OSError as e:
        print(f"Warning: cannot open GUID db {path!r}: {e}", file=sys.stderr)
    return db


# ── Markdown output ──────────────────────────────────────────────────────────

def _md_escape(s: str) -> str:
    """Minimal markdown escaping for table cells."""
    return s.replace('`', "'").replace('|', '\\|')


def emit_markdown(filename: str, pe: dict, guids: list,
                  ascii_strs: list, utf16_strs: list,
                  ptr_tables: list, lea_xrefs: dict) -> str:
    stem = Path(filename).name
    module_name = Path(filename).stem
    lines = []
    A = lines.append

    A(f"# {module_name} — pe_inspect triage")
    A("")
    A(f"Source: `{stem}`  |  "
      f"Generated by `pe_inspect.py`")
    A("")

    # ── 1. PE Header Summary ─────────────────────────────────────────────────
    A("## PE Header Summary")
    A("")
    mach = MACHINE_NAMES.get(pe['machine'], f"{pe['machine']:#06x}")
    subs = SUBSYSTEM_NAMES.get(pe['subsystem'], f"{pe['subsystem']:#06x}")
    A(f"| Field | Value |")
    A(f"|-------|-------|")
    A(f"| File | `{stem}` |")
    A(f"| File size | {pe['file_size']:,} bytes |")
    A(f"| Machine | {mach} |")
    A(f"| Subsystem | {subs} |")
    A(f"| Image base | `{pe['image_base']:#018x}` |")
    A(f"| Entry RVA | `{pe['entry_rva']:#010x}` |")
    A(f"| Size of image | `{pe['size_of_image']:#010x}` ({pe['size_of_image']:,} bytes) |")
    A("")

    A("**Section table:**")
    A("")
    A("| Name | VAddr | VSize | RawOff | RawSize | Flags |")
    A("|------|-------|-------|--------|---------|-------|")
    for s in pe['sections']:
        A(f"| `{s['name']}` "
          f"| `{s['vaddr']:#010x}` "
          f"| `{s['vsize']:#x}` "
          f"| `{s['raw_ptr']:#010x}` "
          f"| `{s['raw_size']:#x}` "
          f"| `{s['characteristics']:#010x}` |")
    A("")

    # ── 2. GUIDs ──────────────────────────────────────────────────────────────
    A("## GUIDs")
    A("")
    if guids:
        A("Scanned all sections with raw data at 16-byte stride; skips DISCARDABLE. "
          "Heuristic filter rejects all-zero, all-FF, ≤2 unique bytes, mostly-ASCII. "
          "Hits in code sections may include false positives from T-table regions.")
        A("")
        A("| Section | Offset | RVA | GUID | Notes |")
        A("|---------|--------|-----|------|-------|")
        for g in guids:
            ann = _md_escape(g['annotation']) if g['annotation'] else '—'
            A(f"| `{g['section']}` "
              f"| `{g['sec_off']:#06x}` "
              f"| `{g['rva']:#010x}` "
              f"| `{g['guid']}` "
              f"| {ann} |")
    else:
        A("No plausible GUIDs found in non-code sections.")
    A("")

    # ── 3. Strings ────────────────────────────────────────────────────────────
    A("## Strings")
    A("")

    A("### UTF-16LE (≥4 chars)")
    A("")
    if utf16_strs:
        A("| Section | Offset | RVA | String |")
        A("|---------|--------|-----|--------|")
        for item in utf16_strs:
            s = _md_escape(item['string'])
            A(f"| `{item['section']}` "
              f"| `{item['sec_off']:#06x}` "
              f"| `{item['rva']:#010x}` "
              f"| `{s}` |")
    else:
        A("None found.")
    A("")

    A("### ASCII (≥6 chars)")
    A("")
    if ascii_strs:
        A("| Section | Offset | RVA | String |")
        A("|---------|--------|-----|--------|")
        for item in ascii_strs:
            if item['sec_off'] == -1:
                A(f"| `{item['section']}` | — | — | *{item['string']}* |")
            else:
                s = _md_escape(item['string'][:120])
                A(f"| `{item['section']}` "
                  f"| `{item['sec_off']:#06x}` "
                  f"| `{item['rva']:#010x}` "
                  f"| `{s}` |")
    else:
        A("None found.")
    A("")

    # ── 4. Pointer Tables ─────────────────────────────────────────────────────
    A("## Pointer Tables")
    A("")
    A("Aligned 8-byte runs (≥3 entries) pointing into code — potential dispatch tables "
      "that Ghidra may miss when functions are only reachable through indirection.")
    A("")
    if ptr_tables:
        for pt in ptr_tables:
            A(f"**`{pt['section']}+{pt['sec_off']:#06x}`** "
              f"(`{pt['rva']:#010x}`): "
              f"{len(pt['entries'])} entries")
            A("")
            A("| Slot | File offset | Stored value | → .text RVA |")
            A("|------|-------------|--------------|-------------|")
            for slot, (foff, val, trva) in enumerate(pt['entries']):
                A(f"| {slot} "
                  f"| `{foff:#010x}` "
                  f"| `{val:#018x}` "
                  f"| `{trva:#010x}` |")
            A("")
    else:
        A("No pointer tables detected.")
    A("")

    # ── 5. LEA RIP-relative xrefs ─────────────────────────────────────────────
    A("## LEA RIP-relative Xrefs (.text → data)")
    A("")
    A("Pattern: `48 8D /r` / `4C 8D /r` with ModRM Mod=00, R/M=101 "
      "(covers ModRM bytes 05,0D,15,1D,25,2D,35,3D). "
      "False-positive rate is non-trivial in dense code; treat as leads.")
    A("")
    if lea_xrefs:
        A("| Target | Target (RVA) | Ref count | Source RVAs |")
        A("|--------|--------------|-----------|-------------|")
        for tgt_rva in sorted(lea_xrefs):
            refs = lea_xrefs[tgt_rva]
            _, dsec_name, dsec_off = refs[0]
            src_list = ' '.join(f'`{src:#010x}`' for src, _, __ in refs)
            A(f"| `{dsec_name}+{dsec_off:#06x}` "
              f"| `{tgt_rva:#010x}` "
              f"| {len(refs)} "
              f"| {src_list} |")
    else:
        A("No RIP-relative LEA to data sections found.")
    A("")

    return '\n'.join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='PE32+ triage tool for UEFI modules. Output is markdown.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('binary',
                    help='Path to the PE32+ EFI binary')
    ap.add_argument('--guid-db', metavar='FILE',
                    help='GUID annotation file (GUID + description, one per line)')
    ap.add_argument('--output', metavar='FILE',
                    help='Write markdown output to FILE (default: stdout)')
    args = ap.parse_args()

    try:
        data = Path(args.binary).read_bytes()
    except OSError as e:
        print(f"Error reading {args.binary!r}: {e}", file=sys.stderr)
        sys.exit(1)

    guid_db = load_guid_db(args.guid_db)

    try:
        pe = parse_pe(data)
    except ValueError as e:
        print(f"PE parse error: {e}", file=sys.stderr)
        sys.exit(1)

    guids       = scan_guids(data, pe['sections'], guid_db)
    ascii_strs, utf16_strs = scan_strings(data, pe['sections'])
    ptr_tables  = scan_pointer_tables(data, pe['sections'], pe['image_base'])
    lea_xrefs   = scan_lea_xrefs(data, pe['sections'])

    md = emit_markdown(
        args.binary, pe, guids, ascii_strs, utf16_strs, ptr_tables, lea_xrefs)

    if args.output:
        try:
            Path(args.output).write_text(md, encoding='utf-8')
        except OSError as e:
            print(f"Error writing {args.output!r}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(md)


if __name__ == '__main__':
    main()
