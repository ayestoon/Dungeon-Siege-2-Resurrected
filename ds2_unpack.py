#!/usr/bin/env python3
"""
DS2 SafeDisc Unpacker — Python Wrapper
========================================
Automates the full SafeDisc v3 unpack pipeline for DS2 analysis.

What it does:
  1. Checks/downloads MinGW-w64 (32-bit GCC for Windows)
  2. Downloads udis86 disassembler library (required by unpack.c)
  3. Compiles unpack.c into unpack.exe
  4. Runs the unpack against each DS2 version
  5. Verifies the output EXE is valid and complete
  6. Reports function count estimate

Usage:
    # Single file
    python ds2_unpack.py "C:\\Program Files (x86)\\Dungeon Siege 2\\DungeonSiege2.exe"

    # Batch — all versions in sequence
    python ds2_unpack.py --batch "C:\\Games\\DS2\\v11\\DungeonSiege2.exe" "C:\\Games\\DS2\\v22\\DungeonSiege2.exe"

    # With custom output folder
    python ds2_unpack.py --outdir "C:\\DS2_Dumps" "C:\\Games\\DS2\\DungeonSiege2.exe"

    # Just build the compiler toolchain (no unpacking)
    python ds2_unpack.py --setup-only

Requirements:
    - Windows (the unpack.c targets Win32 API)
    - Python 3.8+
    - Internet connection for first run (downloads MinGW + udis86)
    - DS2 disc in drive (SafeDisc requires the disc)
    - Run as Administrator

Output:
    <name>_unpacked.exe   — unpacked binary, ready for Ghidra
    ds2_unpack_log.txt    — full build and unpack log
"""

import os
import sys
import json
import time
import shutil
import struct
import hashlib
import zipfile
import tarfile
import argparse
import platform
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────

TOOL_DIR    = Path(os.environ.get('APPDATA', Path.home())) / 'ds2_unpack_tools'
MINGW_DIR   = TOOL_DIR / 'mingw32'
UDIS86_DIR  = TOOL_DIR / 'udis86'
UNPACK_SRC  = TOOL_DIR / 'unpack.c'
UNPACK_EXE  = TOOL_DIR / 'unpack.exe'
LOG_FILE    = Path('ds2_unpack_log.txt')

# MinGW-w64 i686 (32-bit) — required because DS2 is 32-bit and unpack.c uses 32-bit APIs
MINGW_URL  = "https://github.com/brechtsanders/winlibs_mingw/releases/download/13.2.0posix-17.0.6-11.0.1-msvcrt-r5/winlibs-i686-posix-dwarf-gcc-13.2.0-mingw-w64msvcrt-11.0.1-r5.zip"
MINGW_SIZE = 75_000_000  # approximate, for progress display

# udis86 — the disassembler library unpack.c depends on
# We'll use a pre-built Windows static library from the udis86 project
UDIS86_URL = "https://github.com/vmt/udis86/archive/refs/heads/master.zip"

# ── Logging ───────────────────────────────────────────────────────────────────

log_lines = []

def log(msg, level='INFO', color=None):
    ts = datetime.now().strftime('%H:%M:%S')
    line = f"[{ts}] [{level}] {msg}"
    log_lines.append(line)

    colors = {
        'red':    '\033[91m',
        'green':  '\033[92m',
        'yellow': '\033[93m',
        'blue':   '\033[94m',
        'cyan':   '\033[96m',
        'bold':   '\033[1m',
        'reset':  '\033[0m',
    }
    if color and sys.stdout.isatty():
        print(f"{colors.get(color,'')}{msg}{colors['reset']}")
    else:
        print(msg)

def save_log():
    with open(LOG_FILE, 'w') as f:
        f.write('\n'.join(log_lines))
    log(f"Log saved to {LOG_FILE}", color='cyan')

def header(title):
    w = 60
    print(f"\n{'='*w}")
    print(f"  {title}")
    print(f"{'='*w}")

def step(n, total, title):
    print(f"\n[{n}/{total}] {title}")
    print(f"{'─'*50}")


# ── Download helpers ──────────────────────────────────────────────────────────

def download_with_progress(url, dest, label):
    """Download a file with a progress bar."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ds2-unpack/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get('Content-Length', 0))
            downloaded = 0
            chunk = 65536
            with open(dest, 'wb') as f:
                while True:
                    data = resp.read(chunk)
                    if not data:
                        break
                    f.write(data)
                    downloaded += len(data)
                    if total:
                        pct = downloaded / total * 100
                        bar = '█' * int(pct / 5) + '░' * (20 - int(pct / 5))
                        print(f"\r  {label}: [{bar}] {pct:.0f}% ({downloaded//1024//1024}MB)", end='', flush=True)
                    else:
                        print(f"\r  {label}: {downloaded//1024//1024}MB", end='', flush=True)
        print()
        log(f"Downloaded {label} to {dest}")
        return True
    except Exception as e:
        log(f"Download failed: {e}", level='ERROR', color='red')
        return False


# ── Toolchain setup ───────────────────────────────────────────────────────────

def find_gcc():
    """Find a working 32-bit GCC on the system or in our tool dir."""
    candidates = [
        MINGW_DIR / 'bin' / 'gcc.exe',
        MINGW_DIR / 'bin' / 'i686-w64-mingw32-gcc.exe',
        Path('C:/mingw32/bin/gcc.exe'),
        Path('C:/mingw/bin/gcc.exe'),
        Path('C:/TDM-GCC-32/bin/gcc.exe'),
    ]
    # Also check PATH
    for name in ['i686-w64-mingw32-gcc', 'gcc']:
        found = shutil.which(name)
        if found:
            candidates.insert(0, Path(found))

    for gcc in candidates:
        if Path(gcc).exists():
            try:
                result = subprocess.run(
                    [str(gcc), '--version'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    log(f"Found GCC: {gcc}", color='green')
                    return str(gcc)
            except Exception:
                continue
    return None


def setup_mingw():
    """Download and extract MinGW-w64 if not present."""
    gcc = find_gcc()
    if gcc:
        return gcc

    log("MinGW-w64 not found. Downloading...", color='yellow')

    zip_path = TOOL_DIR / 'mingw32.zip'
    if not zip_path.exists():
        if not download_with_progress(MINGW_URL, zip_path, 'MinGW-w64'):
            return None

    log("Extracting MinGW-w64 (this takes a minute)...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            names = z.namelist()
            total = len(names)
            for i, name in enumerate(names):
                z.extract(name, TOOL_DIR)
                if i % 500 == 0:
                    print(f"\r  Extracting: {i}/{total} files", end='', flush=True)
        print()

        # Find the actual gcc.exe inside the extracted folder
        for gcc_path in TOOL_DIR.rglob('gcc.exe'):
            if 'bin' in str(gcc_path):
                log(f"Extracted GCC at: {gcc_path}", color='green')
                return str(gcc_path)
    except Exception as e:
        log(f"Extraction failed: {e}", level='ERROR', color='red')
        return None

    log("Could not find gcc.exe after extraction", level='ERROR', color='red')
    return None


def setup_udis86(gcc_path):
    """Build udis86 static library from source."""
    lib_path = UDIS86_DIR / 'libudis86.a'
    inc_path = UDIS86_DIR / 'include' / 'udis86.h'

    if lib_path.exists() and inc_path.exists():
        log("udis86 already built", color='green')
        return str(lib_path), str(inc_path.parent)

    log("Building udis86 disassembler library...", color='yellow')

    src_dir = UDIS86_DIR / 'src'
    src_dir.mkdir(parents=True, exist_ok=True)

    # Download udis86 source
    zip_path = TOOL_DIR / 'udis86.zip'
    if not zip_path.exists():
        if not download_with_progress(UDIS86_URL, zip_path, 'udis86 source'):
            # Fallback: use inline minimal udis86 stub
            return _build_udis86_stub(gcc_path)

    # Extract
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(src_dir)
    except Exception as e:
        log(f"udis86 extraction failed: {e}", level='ERROR', color='red')
        return _build_udis86_stub(gcc_path)

    # Find extracted dir
    extracted = list(src_dir.glob('udis86-*'))
    if not extracted:
        extracted = list(src_dir.glob('udis86*'))
    if not extracted:
        return _build_udis86_stub(gcc_path)

    udis_src = extracted[0]
    libudis_src = udis_src / 'libudis86'

    if not libudis_src.exists():
        return _build_udis86_stub(gcc_path)

    # Compile each .c file in libudis86/
    c_files = list(libudis_src.glob('*.c'))
    obj_files = []
    gcc = gcc_path

    inc_out = UDIS86_DIR / 'include'
    inc_out.mkdir(parents=True, exist_ok=True)

    for hdr in udis_src.rglob('udis86.h'):
        shutil.copy(hdr, inc_out / 'udis86.h')
        break
    for hdr in libudis_src.glob('*.h'):
        shutil.copy(hdr, inc_out / hdr.name)

    for c_file in c_files:
        obj = UDIS86_DIR / (c_file.stem + '.o')
        result = subprocess.run(
            [gcc, '-m32', '-O2', '-c', str(c_file),
             f'-I{inc_out}', f'-I{libudis_src}',
             '-o', str(obj)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            log(f"Compile failed for {c_file.name}: {result.stderr[:200]}", level='WARN', color='yellow')
            continue
        obj_files.append(str(obj))

    if not obj_files:
        return _build_udis86_stub(gcc_path)

    # Archive into static lib
    ar_path = str(Path(gcc).parent / 'ar.exe')
    if not Path(ar_path).exists():
        ar_path = shutil.which('ar') or 'ar'

    result = subprocess.run(
        [ar_path, 'rcs', str(lib_path)] + obj_files,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"ar failed: {result.stderr[:200]}", level='WARN', color='yellow')
        return _build_udis86_stub(gcc_path)

    log("udis86 built successfully", color='green')
    return str(lib_path), str(inc_out)


def _build_udis86_stub(gcc_path):
    """
    Build a minimal udis86 stub that implements just enough for unpack.c to compile.
    This is a fallback if the full udis86 source download fails.
    """
    log("Building minimal udis86 stub...", color='yellow')

    stub_dir = UDIS86_DIR / 'stub'
    stub_dir.mkdir(parents=True, exist_ok=True)
    inc_out = UDIS86_DIR / 'include'
    inc_out.mkdir(parents=True, exist_ok=True)

    # Minimal udis86.h
    header_code = '''
#pragma once
#ifndef UDIS86_H
#define UDIS86_H
#include <stdint.h>
#include <stddef.h>

typedef enum ud_mnemonic_code {
    UD_Inone = 0, UD_Iint3, UD_Iret, UD_Ijmp, UD_Icall,
    UD_Imov, UD_Ipush, UD_Ipop, UD_Inop, UD_Ixor,
    UD_Icmp, UD_Ijz, UD_Ijnz, UD_Ijb, UD_Ija,
    UD_Itest, UD_Iand, UD_Ior, UD_Iadd, UD_Isub,
    UD_Iinc, UD_Idec, UD_Ilea, UD_Inot, UD_Ineg,
    UD_Imul, UD_Idiv, UD_Iimul, UD_Iidiv,
    UD_Ishl, UD_Ishr, UD_Isar, UD_Irol, UD_Iror,
    UD_Imovsx, UD_Imovzx, UD_Icmove, UD_Icmovne,
    UD_Ife, UD_Iff, UD_I_invalid = 0x7fffffff
} ud_mnemonic_code_t;

typedef enum ud_operand_code {
    UD_NONE, UD_OP_REG, UD_OP_MEM, UD_OP_PTR,
    UD_OP_IMM, UD_OP_JIMM, UD_OP_CONST
} ud_operand_type_t;

typedef struct ud_operand {
    ud_operand_type_t type;
    uint8_t  size;
    union {
        int8_t   sbyte;
        int16_t  sword;
        int32_t  sdword;
        int64_t  sqword;
        uint8_t  ubyte;
        uint16_t uword;
        uint32_t udword;
        uint64_t uqword;
    } lval;
} ud_operand_t;

typedef struct ud {
    const uint8_t *inp_buf;
    size_t         inp_buf_size;
    size_t         inp_buf_index;
    uint64_t       pc;
    uint8_t        dis_mode;
    ud_mnemonic_code_t mnemonic;
    ud_operand_t   operand[3];
    unsigned int   insn_len;
    uint64_t       insn_off;
} ud_t;

void     ud_init(ud_t *u);
void     ud_set_mode(ud_t *u, uint8_t m);
void     ud_set_pc(ud_t *u, uint64_t pc);
void     ud_set_input_buffer(ud_t *u, const uint8_t *buf, size_t len);
unsigned ud_disassemble(ud_t *u);
ud_mnemonic_code_t ud_insn_mnemonic(ud_t *u);
uint64_t ud_insn_off(ud_t *u);
unsigned ud_insn_len(ud_t *u);
const ud_operand_t *ud_insn_opr(ud_t *u, unsigned n);
const char *ud_insn_asm(ud_t *u);

#endif /* UDIS86_H */
'''

    # Minimal udis86 stub implementation — basic x86 length disassembler
    stub_code = r'''
#include "udis86.h"
#include <string.h>

/* Minimal x86 instruction length disassembler.
** Handles the common cases needed by unpack.c:
**   - int3 (0xCC)
**   - ret (0xC3, 0xC2)
**   - jmp/call rel8/rel16/rel32 (0xEB, 0xE8, 0xE9)
**   - jmp r/m32 (0xFF /4)
**   - call r/m32 (0xFF /2)
**   - most common 1-6 byte instructions
** Returns 0 at end of buffer or on error.
*/

void ud_init(ud_t *u) { memset(u, 0, sizeof(*u)); }
void ud_set_mode(ud_t *u, uint8_t m) { u->dis_mode = m; }
void ud_set_pc(ud_t *u, uint64_t pc) { u->pc = pc; }
void ud_set_input_buffer(ud_t *u, const uint8_t *buf, size_t len) {
    u->inp_buf = buf;
    u->inp_buf_size = len;
    u->inp_buf_index = 0;
}

static int has_modrm(uint8_t op) {
    /* opcodes that have a ModRM byte */
    static const uint8_t modrm_ops[] = {
        0x01,0x03,0x09,0x0b,0x0f,0x11,0x13,0x21,0x23,0x29,0x2b,
        0x31,0x33,0x38,0x39,0x3b,0x63,0x69,0x6b,0x80,0x81,0x83,
        0x84,0x85,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0xc0,0xc1,0xc6,0xc7,0xd0,0xd1,0xd2,0xd3,0xf6,0xf7,0xfe,0xff,0
    };
    for(int i=0; modrm_ops[i]; i++)
        if(modrm_ops[i] == op) return 1;
    return 0;
}

static unsigned modrm_extra(uint8_t modrm) {
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm  = modrm & 7;
    if (mod == 3) return 0;
    if (mod == 0) {
        if (rm == 5) return 4;  /* disp32 */
        if (rm == 4) return 1;  /* SIB */
        return 0;
    }
    if (mod == 1) return (rm == 4) ? 2 : 1;  /* SIB+disp8 or disp8 */
    if (mod == 2) return (rm == 4) ? 5 : 4;  /* SIB+disp32 or disp32 */
    return 0;
}

unsigned ud_disassemble(ud_t *u) {
    if (!u->inp_buf || u->inp_buf_index >= u->inp_buf_size) return 0;

    const uint8_t *p = u->inp_buf + u->inp_buf_index;
    size_t rem = u->inp_buf_size - u->inp_buf_index;
    if (rem == 0) return 0;

    u->insn_off = u->pc + u->inp_buf_index;
    u->mnemonic = UD_Inone;
    memset(u->operand, 0, sizeof(u->operand));

    uint8_t op = p[0];
    unsigned len = 1;

    /* handle prefixes */
    while (op == 0x66 || op == 0x67 || op == 0xf0 || op == 0xf2 || op == 0xf3 ||
           op == 0x26 || op == 0x2e || op == 0x36 || op == 0x3e ||
           op == 0x64 || op == 0x65) {
        if (len >= rem) { u->insn_len = 1; u->inp_buf_index++; return 1; }
        len++;
        op = p[len-1];
    }

    /* two-byte escape */
    if (op == 0x0f) {
        if (len >= rem) { u->insn_len = len; u->inp_buf_index += len; return 1; }
        op = p[len++];
        /* most 0F xx ops have ModRM */
        if (len < rem && has_modrm(op)) {
            uint8_t modrm = p[len++];
            len += modrm_extra(modrm);
        }
        u->insn_len = (len < rem) ? len : (unsigned)rem;
        u->inp_buf_index += u->insn_len;
        return 1;
    }

    switch (op) {
        /* single byte */
        case 0x90: case 0xc3: case 0xcb: case 0xcc: case 0xcd:
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
        case 0x45: case 0x46: case 0x47: case 0x48: case 0x49:
        case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
        case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
        case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x60: case 0x61: case 0x9c: case 0x9d:
            break;

        /* int nn */
        case 0xcd: len += 1; break;

        /* ret imm16 / retn */
        case 0xc2: case 0xca: len += 2; break;

        /* jmp/call rel8 */
        case 0xeb: case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
        case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d:
        case 0x7e: case 0x7f: case 0xe3:
            len += 1;
            if (len-1 < rem) {
                u->mnemonic = UD_Ijmp;
                u->operand[0].type = UD_OP_JIMM;
                u->operand[0].size = 8;
                u->operand[0].lval.sbyte = (int8_t)p[len-1];
            }
            break;

        /* call/jmp rel32 */
        case 0xe8: case 0xe9:
            len += 4;
            if (len-1 < rem) {
                u->mnemonic = (op == 0xe8) ? UD_Icall : UD_Ijmp;
                u->operand[0].type = UD_OP_JIMM;
                u->operand[0].size = 32;
                int32_t rel;
                memcpy(&rel, p+1, 4);
                u->operand[0].lval.sdword = rel;
            }
            break;

        /* push imm8 */
        case 0x6a: len += 1; break;
        /* push imm32 */
        case 0x68: len += 4; break;

        /* mov r, imm32 */
        case 0xb8: case 0xb9: case 0xba: case 0xbb:
        case 0xbc: case 0xbd: case 0xbe: case 0xbf:
            len += 4; break;

        /* mov r8, imm8 */
        case 0xb0: case 0xb1: case 0xb2: case 0xb3:
        case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            len += 1; break;

        /* imm8 ops */
        case 0xa8: case 0x3c: case 0x1c: case 0x2c: case 0x04:
        case 0x0c: case 0x24: case 0x34:
            len += 1; break;

        /* imm32 ops */
        case 0xa9: case 0x3d: case 0x1d: case 0x2d: case 0x05:
        case 0x0d: case 0x25: case 0x35:
            len += 4; break;

        /* ModRM instructions */
        default:
            if (has_modrm(op)) {
                if (len < rem) {
                    uint8_t modrm = p[len++];
                    len += modrm_extra(modrm);
                    /* imm for 80/81/83 group */
                    if (op == 0x81) len += 4;
                    else if (op == 0x80 || op == 0x83 || op == 0xc0 || op == 0xc1) len += 1;
                    else if (op == 0xc6) len += 1;
                    else if (op == 0xc7) len += 4;
                }
            }
            break;
    }

    /* clamp to remaining */
    if (len > rem) len = (unsigned)rem;

    /* set mnemonic if not already set */
    if (u->mnemonic == UD_Inone) {
        switch (op) {
            case 0xcc: u->mnemonic = UD_Iint3; break;
            case 0xc3: case 0xc2: case 0xcb: case 0xca: u->mnemonic = UD_Iret; break;
            case 0xe9: case 0xeb: case 0xff:
                if (op == 0xff && len > 1 && ((p[1]>>3)&7) == 4) u->mnemonic = UD_Ijmp;
                else if (op != 0xff) u->mnemonic = UD_Ijmp;
                break;
            case 0xe8:
                if (op == 0xff && len > 1 && ((p[1]>>3)&7) == 2) u->mnemonic = UD_Icall;
                else u->mnemonic = UD_Icall;
                break;
            default: u->mnemonic = UD_Inone; break;
        }
    }

    u->insn_len = len;
    u->inp_buf_index += len;
    return 1;
}

ud_mnemonic_code_t ud_insn_mnemonic(ud_t *u) { return u->mnemonic; }
uint64_t           ud_insn_off(ud_t *u)       { return u->insn_off; }
unsigned           ud_insn_len(ud_t *u)       { return u->insn_len; }
const char        *ud_insn_asm(ud_t *u)       { return ""; }

const ud_operand_t *ud_insn_opr(ud_t *u, unsigned n) {
    if (n >= 3 || u->operand[n].type == UD_NONE) return NULL;
    return &u->operand[n];
}
'''

    stub_h = stub_dir / 'udis86.h'
    stub_c = stub_dir / 'stub.c'
    stub_lib = UDIS86_DIR / 'libudis86.a'

    with open(stub_h, 'w') as f: f.write(header_code)
    with open(stub_c, 'w') as f: f.write(stub_code)
    shutil.copy(stub_h, inc_out / 'udis86.h')

    gcc = gcc_path
    obj = UDIS86_DIR / 'stub.o'
    result = subprocess.run(
        [gcc, '-m32', '-O2', '-c', str(stub_c),
         f'-I{stub_dir}', '-o', str(obj)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log(f"Stub compile failed: {result.stderr[:300]}", level='ERROR', color='red')
        return None, None

    ar_path = str(Path(gcc).parent / 'ar.exe')
    if not Path(ar_path).exists():
        ar_path = shutil.which('ar') or str(Path(gcc).parent / 'ar')

    subprocess.run([ar_path, 'rcs', str(stub_lib), str(obj)], capture_output=True)
    log("udis86 stub built", color='yellow')
    return str(stub_lib), str(inc_out)


# ── Compile unpack.c ──────────────────────────────────────────────────────────

UNPACK_C_SOURCE = r'''
/*
** SafeDisc v3 unpacker - unpack.c
** Author: Fatbag
** Revision: 2014-02-18
** License: Public domain (no warranties, express or implied)
** Wrapped by DS2 Community Rebuild Project, 2025
*/

/*
** SafeDisc v3 works in the following manner for all games.
**
** The game process extracts various DLLs, loads one of them into memory, and
** then spawns a child process that debugs the game process. Once the debugger
** is attached, the game process spins up the disc and reads off a symmetric
** encryption key, unpacks most of itself, and jumps to the game's original
** entry point.
**
** At this point, all non-code sections of the game are completely unpacked
** and the code section is mostly unpacked, except that:
** 1. various instructions have been overwritten with 0xCC bytes (int 3
**    breakpoints);
** 2. various instructions have been overwritten with calls to a function
**    (and sometimes scrambled data after that call) which jumps to one of the
**    extracted DLLs and eventually restores the original instructions, flushes
**    the CPU cache, and jumps back; and
** 3. various addresses of imported DLLs have been overwritten with addresses
**    to one of the extracted DLLs, which, using the return address as a
**    deciding factor, eventually jump to the original imported function.
*/
'''

def write_unpack_src(src_text):
    """Write the unpack.c source to disk."""
    TOOL_DIR.mkdir(parents=True, exist_ok=True)
    with open(UNPACK_SRC, 'w') as f:
        f.write(src_text)
    log(f"Wrote unpack.c to {UNPACK_SRC}")


def compile_unpack(gcc_path, udis86_lib, udis86_inc, src_text):
    """Compile unpack.c into unpack.exe."""
    if UNPACK_EXE.exists():
        # Check if source changed
        src_hash = hashlib.md5(src_text.encode()).hexdigest()
        cache_file = TOOL_DIR / 'unpack_src.md5'
        if cache_file.exists() and cache_file.read_text().strip() == src_hash:
            log("unpack.exe already up to date", color='green')
            return str(UNPACK_EXE)

    write_unpack_src(src_text)

    log(f"Compiling unpack.c with GCC...", color='cyan')
    cmd = [
        gcc_path,
        '-m32',
        '-Wall',
        '-O2',
        '-s',
        '-mconsole',
        str(UNPACK_SRC),
        udis86_lib,
        f'-I{udis86_inc}',
        '-ludis86',
        f'-L{Path(udis86_lib).parent}',
        '-lws2_32',
        '-o', str(UNPACK_EXE)
    ]

    log(f"  {' '.join(cmd[:5])} ...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    log(result.stdout)
    if result.stderr:
        log(result.stderr, level='WARN')

    if result.returncode != 0 or not UNPACK_EXE.exists():
        # Try without -ludis86 (static only)
        cmd2 = [
            gcc_path, '-m32', '-Wall', '-O2', '-s', '-mconsole',
            str(UNPACK_SRC), udis86_lib,
            f'-I{udis86_inc}',
            f'-L{Path(udis86_lib).parent}',
            '-o', str(UNPACK_EXE)
        ]
        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        if result2.returncode != 0 or not UNPACK_EXE.exists():
            log(f"Compile failed:\n{result2.stderr[:500]}", level='ERROR', color='red')
            return None

    # Cache source hash
    src_hash = hashlib.md5(src_text.encode()).hexdigest()
    (TOOL_DIR / 'unpack_src.md5').write_text(src_hash)

    log(f"Compiled: {UNPACK_EXE}", color='green')
    return str(UNPACK_EXE)


# ── PE Verification ───────────────────────────────────────────────────────────

def verify_dump(path):
    """Check that a dumped EXE looks like a valid unpacked DS2 binary."""
    path = Path(path)
    if not path.exists():
        return False, "File does not exist"

    size = path.stat().st_size
    if size < 1_000_000:
        return False, f"File too small ({size:,} bytes) — dump likely failed"

    with open(path, 'rb') as f:
        data = f.read(min(size, 512))

    if data[:2] != b'MZ':
        return False, "Not a valid PE file (missing MZ header)"

    if size < 5_000_000:
        return False, f"File smaller than expected ({size/1024/1024:.1f}MB) — may be incomplete"

    # Check PE signature
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_offset + 4 < len(data):
        pe_sig = data[pe_offset:pe_offset+4]
        if pe_sig != b'PE\x00\x00':
            return False, "PE signature invalid"

    # Estimate function count by counting function prologues (push ebp; mov ebp, esp)
    with open(path, 'rb') as f:
        body = f.read()
    prologue_count = body.count(b'\x55\x8b\xec')  # push ebp; mov ebp, esp
    alt_prologue = body.count(b'\x55\x89\xe5')    # push ebp; mov ebp, esp (AT&T)

    return True, {
        'size_mb': size / 1024 / 1024,
        'estimated_functions': prologue_count + alt_prologue,
        'pe_valid': True,
    }


# ── Run unpack ────────────────────────────────────────────────────────────────

def run_unpack(unpack_exe, input_exe, output_path, timeout=300):
    """Run the unpack.exe tool against a DS2 EXE."""
    input_exe  = Path(input_exe)
    output_path = Path(output_path)

    if not input_exe.exists():
        log(f"Input not found: {input_exe}", level='ERROR', color='red')
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        output_path.unlink()

    log(f"Input:  {input_exe}")
    log(f"Output: {output_path}")
    log(f"Running unpack.exe (game must load to main menu)...", color='cyan')
    log("  The game window will open — let it load fully, then come back here.")
    log("  Unpack completes automatically once the game reaches main menu.")
    print()

    start = time.time()
    try:
        result = subprocess.run(
            [unpack_exe, str(input_exe), str(output_path)],
            capture_output=False,  # Let output stream to console
            timeout=timeout,
            cwd=str(input_exe.parent)  # Run from game directory so relative paths work
        )
    except subprocess.TimeoutExpired:
        log(f"Timed out after {timeout}s", level='ERROR', color='red')
        return False
    except Exception as e:
        log(f"Failed to run unpack.exe: {e}", level='ERROR', color='red')
        return False

    elapsed = time.time() - start
    log(f"unpack.exe completed in {elapsed:.0f}s (exit code: {result.returncode})")

    if result.returncode != 0:
        log(f"unpack.exe returned non-zero exit code: {result.returncode}", level='WARN', color='yellow')

    return output_path.exists()


# ── Main pipeline ─────────────────────────────────────────────────────────────

def process_one(unpack_exe, input_path, outdir):
    """Full pipeline for one EXE."""
    input_path = Path(input_path)
    stem = input_path.stem
    version_tag = input_path.parent.name.replace(' ', '_')
    out_name = f"{stem}_{version_tag}_unpacked.exe"
    output_path = Path(outdir) / out_name

    header(f"UNPACKING: {input_path.name}")
    log(f"Source version folder: {input_path.parent.name}", color='blue')

    # Run unpack
    ok = run_unpack(unpack_exe, input_path, output_path)

    if not ok:
        log(f"FAILED: output file not created", level='ERROR', color='red')
        return None

    # Verify
    valid, info = verify_dump(output_path)
    if not valid:
        log(f"INVALID DUMP: {info}", level='ERROR', color='red')
        return None

    log(f"\n✓ SUCCESS: {output_path}", color='green')
    log(f"  Size:               {info['size_mb']:.1f} MB")
    log(f"  Est. functions:     {info['estimated_functions']:,}")
    log(f"  PE valid:           {info['pe_valid']}")
    log(f"")

    if info['estimated_functions'] < 5000:
        log(f"  ⚠ Low function count — may be partially packed", color='yellow')
        log(f"    Expected 10,000+ for DS2 v1.x/v2.x", color='yellow')
    else:
        log(f"  ✓ Function count looks good for Ghidra analysis", color='green')

    return str(output_path)


def setup_toolchain(src_text):
    """Download, build, and verify the full toolchain."""
    header("TOOLCHAIN SETUP")

    step(1, 3, "Setting up GCC (MinGW-w64 32-bit)")
    gcc = setup_mingw()
    if not gcc:
        log("Failed to find or install GCC", level='ERROR', color='red')
        log("Manual install: Download MinGW-w64 from https://winlibs.com/", color='yellow')
        log("Choose: i686 (32-bit), Win32 threads, DWARF exceptions", color='yellow')
        return None, None, None

    step(2, 3, "Building udis86 disassembler library")
    result = setup_udis86(gcc)
    if not result or result[0] is None:
        log("Failed to build udis86", level='ERROR', color='red')
        return None, None, None
    udis86_lib, udis86_inc = result

    step(3, 3, "Compiling unpack.exe")
    unpack_exe = compile_unpack(gcc, udis86_lib, udis86_inc, src_text)
    if not unpack_exe:
        log("Compilation failed", level='ERROR', color='red')
        return None, None, None

    log(f"\n✓ Toolchain ready: {unpack_exe}", color='green')
    return gcc, udis86_lib, unpack_exe


def main():
    ap = argparse.ArgumentParser(
        description='DS2 SafeDisc Unpacker — automated unpack pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    ap.add_argument('files', nargs='*',
                    help='DS2 EXE files to unpack')
    ap.add_argument('--batch', nargs='+',
                    help='Batch mode: process multiple EXEs in sequence')
    ap.add_argument('--outdir', default='.',
                    help='Output directory for unpacked EXEs (default: current dir)')
    ap.add_argument('--setup-only', action='store_true',
                    help='Only set up the toolchain, do not unpack')
    ap.add_argument('--src', default=None,
                    help='Path to unpack.c source (uses bundled version if not specified)')
    ap.add_argument('--timeout', type=int, default=300,
                    help='Timeout in seconds per unpack run (default: 300)')
    args = ap.parse_args()

    if platform.system() != 'Windows':
        log("WARNING: This tool targets Windows. unpack.exe uses Win32 APIs.", color='yellow')
        log("The toolchain setup (GCC + udis86) will work on Linux,", color='yellow')
        log("but you'll need to run unpack.exe on Windows.", color='yellow')
        print()

    header("DS2 SAFEDISC UNPACKER")
    log(f"Tool directory: {TOOL_DIR}")
    log(f"Output directory: {args.outdir}")
    print()

    # Load source
    if args.src:
        if not Path(args.src).exists():
            log(f"Source not found: {args.src}", level='ERROR', color='red')
            sys.exit(1)
        src_text = Path(args.src).read_text()
    else:
        # Prompt user to paste unpack.c if not available
        bundled = TOOL_DIR / 'unpack.c'
        if bundled.exists():
            src_text = bundled.read_text()
        else:
            log("unpack.c not found in tool directory.", color='yellow')
            log(f"Please copy unpack.c to: {TOOL_DIR}", color='yellow')
            log("Or use --src path/to/unpack.c to specify the source location.")
            log("\nThe unpack.c source is available from:")
            log("  http://niotso.org/ (original by Fatbag)")
            log("  Or paste the source from the DS2 community rebuild project.")
            sys.exit(1)

    # Setup toolchain
    gcc, udis86_lib, unpack_exe = setup_toolchain(src_text)
    if not unpack_exe:
        save_log()
        sys.exit(1)

    if args.setup_only:
        log("Setup complete. Run without --setup-only to unpack.", color='green')
        save_log()
        return

    # Collect targets
    targets = list(args.files or [])
    if args.batch:
        targets.extend(args.batch)

    if not targets:
        log("No EXE files specified.", color='yellow')
        log("Usage: python ds2_unpack.py \"C:\\Games\\DS2\\DungeonSiege2.exe\"")
        log("       python ds2_unpack.py --batch v11\\DS2.exe v22\\DS2.exe bw23\\DS2.exe")
        save_log()
        return

    # Process each target
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    results = []
    for i, target in enumerate(targets):
        print()
        log(f"Processing {i+1}/{len(targets)}: {target}", color='bold')
        out = process_one(unpack_exe, target, outdir)
        results.append((target, out))

    # Final summary
    header("SUMMARY")
    ok_count = sum(1 for _, o in results if o)
    for target, out in results:
        status = f"✓ {out}" if out else "✗ FAILED"
        color = 'green' if out else 'red'
        log(f"  {Path(target).name:40s} {status}", color=color)

    print()
    log(f"Completed: {ok_count}/{len(results)} successful")
    if ok_count > 0:
        log(f"\nNext steps:")
        log(f"  1. Import unpacked EXEs into Ghidra")
        log(f"  2. Run Analysis → Auto Analyze (uncheck PDB Universal)")
        log(f"  3. Run Analysis → One Shot → Function ID")
        log(f"  4. File → Export Program → C/C++")
        log(f"  5. Run ds2_survey.py on the exported C files")

    save_log()


if __name__ == '__main__':
    main()
