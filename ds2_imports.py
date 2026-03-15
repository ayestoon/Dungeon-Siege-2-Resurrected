#!/usr/bin/env python3
"""
DS2 PE Import Scanner
======================
Reads the Import Address Table directly from DS2 EXE files.
No Ghidra needed — runs on the raw .exe files.

Finds:
  - Every DLL the game loads
  - Every function imported from each DLL
  - Flags network/GameSpy related imports

Usage:
    python ds2_imports.py "C:/Program Files/Dungeon Siege 2/DungeonSiege2.exe"
    python ds2_imports.py --dir "C:/Program Files/Dungeon Siege 2"
"""

import os
import re
import sys
import struct
import argparse
from pathlib import Path
from collections import defaultdict


# ── PE Parser ─────────────────────────────────────────────────────────────────

def read_pe_imports(filepath):
    """Parse PE Import Directory Table from an EXE/DLL."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # DOS header
    if data[:2] != b'MZ':
        return None, "Not a valid PE file"

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return None, "PE signature not found"

    # COFF header
    machine = struct.unpack_from('<H', data, pe_offset+4)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset+6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset+20)[0]
    opt_header_offset = pe_offset + 24

    # Optional header magic (PE32 vs PE32+)
    magic = struct.unpack_from('<H', data, opt_header_offset)[0]
    is_pe32_plus = magic == 0x20B

    # Image base and data directories
    if is_pe32_plus:
        image_base = struct.unpack_from('<Q', data, opt_header_offset+24)[0]
        import_dir_offset = opt_header_offset + 104 + (1 * 8)  # DataDirectory[1]
    else:
        image_base = struct.unpack_from('<I', data, opt_header_offset+28)[0]
        import_dir_offset = opt_header_offset + 96 + (1 * 8)  # DataDirectory[1]

    import_rva = struct.unpack_from('<I', data, import_dir_offset)[0]
    import_size = struct.unpack_from('<I', data, import_dir_offset+4)[0]

    if import_rva == 0:
        return None, "No import directory"

    # Section headers — need to convert RVA to file offset
    sections_offset = opt_header_offset + opt_header_size
    sections = []
    for i in range(num_sections):
        sec_off = sections_offset + i * 40
        name = data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize   = struct.unpack_from('<I', data, sec_off+8)[0]
        vaddr   = struct.unpack_from('<I', data, sec_off+12)[0]
        rawsize = struct.unpack_from('<I', data, sec_off+16)[0]
        rawoff  = struct.unpack_from('<I', data, sec_off+20)[0]
        sections.append((name, vaddr, vsize, rawoff, rawsize))

    def rva_to_offset(rva):
        for name, vaddr, vsize, rawoff, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawoff + (rva - vaddr)
        return None

    def read_string(offset):
        end = data.find(b'\x00', offset)
        if end == -1: return ''
        return data[offset:end].decode('ascii', errors='replace')

    # Parse import descriptors
    imports = {}
    offset = rva_to_offset(import_rva)
    if offset is None:
        return None, f"Could not resolve import RVA 0x{import_rva:x}"

    while True:
        # IMAGE_IMPORT_DESCRIPTOR (20 bytes)
        orig_first_thunk = struct.unpack_from('<I', data, offset)[0]
        name_rva         = struct.unpack_from('<I', data, offset+12)[0]
        first_thunk      = struct.unpack_from('<I', data, offset+16)[0]
        offset += 20

        if name_rva == 0:
            break

        name_offset = rva_to_offset(name_rva)
        if name_offset is None:
            continue
        dll_name = read_string(name_offset).lower()

        # Parse function names from INT (original first thunk)
        thunk_rva = orig_first_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva)
        functions = []

        if thunk_offset:
            while True:
                if is_pe32_plus:
                    thunk_val = struct.unpack_from('<Q', data, thunk_offset)[0]
                    thunk_offset += 8
                    if thunk_val == 0: break
                    if thunk_val & (1 << 63):  # import by ordinal
                        functions.append(f'Ordinal_{thunk_val & 0xFFFF}')
                        continue
                else:
                    thunk_val = struct.unpack_from('<I', data, thunk_offset)[0]
                    thunk_offset += 4
                    if thunk_val == 0: break
                    if thunk_val & 0x80000000:  # import by ordinal
                        functions.append(f'Ordinal_{thunk_val & 0xFFFF}')
                        continue

                hint_rva = thunk_val & (0x7FFFFFFFFFFFFFFF if is_pe32_plus else 0x7FFFFFFF)
                hint_offset = rva_to_offset(hint_rva)
                if hint_offset:
                    func_name = read_string(hint_offset + 2)  # skip hint word
                    functions.append(func_name)

        imports[dll_name] = functions

    return imports, None


# ── Network classifier ─────────────────────────────────────────────────────────

NETWORK_DLLS = {
    # GameSpy
    'gamespy':      ['gamespy', 'gspy', 'gt2', 'peerSB', 'qr2', 'serverbrowsing',
                     'gamestats', 'sake', 'voice2', 'natneg', 'brigades', 'atlas'],
    # Microsoft network
    'winhttp':      ['winhttp'],
    'wininet':      ['wininet'],
    'winsock':      ['ws2_32', 'wsock32', 'mswsock'],
    'directplay':   ['dplayx', 'dpnet', 'dpnhpast', 'dpvoice', 'dplay'],
    # Other online
    'steam':        ['steam_api', 'steamclient'],
    'securom':      ['securom'],
    'safedisc':     ['secdrv'],
}

NETWORK_FUNCS = re.compile(
    r'(WSA|socket|connect|send|recv|bind|listen|Http|Internet|GameSpy|DirectPlay|'
    r'steam_|peer_|natneg|serverBrows|gpConnect|qr2|gt2)',
    re.I
)

def classify_dll(dll_name):
    for category, patterns in NETWORK_DLLS.items():
        for pat in patterns:
            if pat.lower() in dll_name.lower():
                return category
    return None


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_exe(filepath):
    print(f"\n  [{Path(filepath).name}]")
    imports, err = read_pe_imports(filepath)
    if err:
        print(f"    Error: {err}")
        return None

    result = {
        'file': filepath,
        'dlls': {},
        'network': defaultdict(list),
        'gamespy_funcs': [],
        'total_dlls': len(imports),
        'total_imports': sum(len(v) for v in imports.values()),
    }

    for dll, funcs in sorted(imports.items()):
        cat = classify_dll(dll)
        result['dlls'][dll] = {'functions': funcs, 'category': cat}
        if cat:
            result['network'][cat].append(dll)

        # Flag network function imports
        for f in funcs:
            if NETWORK_FUNCS.search(f):
                result['gamespy_funcs'].append((dll, f))

        print(f"    {dll:<35} {len(funcs):>4} imports  {('[' + cat + ']') if cat else ''}")

    print(f"    {'─'*50}")
    print(f"    Total: {result['total_dlls']} DLLs, {result['total_imports']} imports")

    if result['network']:
        print(f"\n    ⚠ Network dependencies:")
        for cat, dlls in result['network'].items():
            print(f"      [{cat}] {', '.join(dlls)}")

    return result


def print_summary(all_results):
    print(f"\n{'='*60}")
    print(f"  NETWORK DEPENDENCY SUMMARY")
    print(f"{'='*60}")

    # Collect all unique network DLLs across all EXEs
    all_network = defaultdict(set)
    all_gamespy_funcs = set()

    for label, result in all_results.items():
        if not result: continue
        for cat, dlls in result['network'].items():
            for dll in dlls:
                all_network[cat].add(dll)
        for dll, func in result['gamespy_funcs']:
            all_gamespy_funcs.add((dll, func))

    if not all_network:
        print("\n  No recognized network DLLs found in import tables.")
        print("  GameSpy may be:")
        print("  1. Loaded dynamically via LoadLibrary() at runtime")
        print("  2. Statically compiled into the EXE")
        print("  3. Using differently-named DLLs")
        print("\n  Check for LoadLibrary calls in the C exports.")
        print("  Search C exports for: LoadLibrary, GetProcAddress")
    else:
        for cat, dlls in sorted(all_network.items()):
            print(f"\n  [{cat.upper()}]")
            for dll in sorted(dlls):
                print(f"    {dll}")

    if all_gamespy_funcs:
        print(f"\n  Network functions imported:")
        for dll, func in sorted(all_gamespy_funcs)[:30]:
            print(f"    {dll} → {func}")

    # Check for dynamic loading hint
    print(f"\n{'='*60}")
    print(f"  NEXT STEPS")
    print(f"{'='*60}")
    print(f"  If GameSpy DLLs not found in imports above:")
    print(f"  → Search C exports for LoadLibrary/GetProcAddress")
    print(f"  → Check game folder for non-obvious DLL names")
    print(f"  → Run: python ds2_imports.py --dir \"<game install folder>\"")
    print(f"     to scan ALL DLLs in the game folder, not just the EXE")


def main():
    ap = argparse.ArgumentParser(description='DS2 PE Import Scanner')
    ap.add_argument('files', nargs='*', help='EXE/DLL files to scan')
    ap.add_argument('--dir', default=None, help='Scan all EXE/DLL files in folder')
    args = ap.parse_args()

    targets = list(args.files)
    if args.dir:
        d = Path(args.dir)
        targets += [str(f) for f in sorted(d.glob('*.exe'))]
        targets += [str(f) for f in sorted(d.glob('*.dll'))]

    if not targets:
        print("Usage:")
        print('  python ds2_imports.py "C:/Games/DS2/DungeonSiege2.exe"')
        print('  python ds2_imports.py --dir "C:/Games/DS2"')
        return

    print(f"\n{'='*60}")
    print(f"  DS2 PE IMPORT SCANNER")
    print(f"{'='*60}")

    all_results = {}
    for t in targets:
        if not os.path.exists(t):
            print(f"  [skip] Not found: {t}")
            continue
        label = Path(t).name
        all_results[label] = scan_exe(t)

    print_summary(all_results)


if __name__ == '__main__':
    main()
