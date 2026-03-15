#!/usr/bin/env python3
"""
DS2 Diff Category Filter
Extracts functions by category from ds2_differ.py cache files.

Usage:
    python ds2_filter.py file_a.c file_b.c --cats threading memory
    python ds2_filter.py file_a.c file_b.c --cats threading --status changed
    python ds2_filter.py file_a.c file_b.c --cats threading memory --output threading_funcs.json
"""
import sys, os, re, json, argparse, difflib
from pathlib import Path

CATS = {
    'memory':    re.compile(r'\b(VirtualAlloc|VirtualFree|HeapAlloc|HeapFree|malloc|free|GlobalAlloc)\b'),
    'hvci':      re.compile(r'\b(VirtualProtect|NtProtect|PAGE_EXECUTE|MEM_COMMIT|PAGE_EXECUTE_READWRITE)\b'),
    'directx':   re.compile(r'\b(IDirect3D|Direct3DCreate|D3D|CreateDevice|d3d8|d3d9)\b', re.I),
    'audio':     re.compile(r'\b(AIL_|miles|mss32|dsound|DirectSound|IDirectSound|waveOut)\b', re.I),
    'tank':      re.compile(r'\b(tank|TankFile|\.sno|siegelet|SiegeTank)\b', re.I),
    'node':      re.compile(r'\b(SiegeNode|NodeGraph|sno_|node_|NodeRef)\b', re.I),
    'timing':    re.compile(r'\b(QueryPerformanceCounter|timeGetTime|GetTickCount|Sleep|frametime)\b', re.I),
    'threading': re.compile(r'\b(CreateThread|WaitForSingle|EnterCriticalSection|InitializeCriticalSection|CloseHandle|TerminateThread|ResumeThread|SuspendThread)\b'),
    'fileio':    re.compile(r'\b(CreateFile|ReadFile|WriteFile|fopen|fread|fwrite)\b'),
    'bw':        re.compile(r'\b(broken_world|siegelet_load|bw_|expansion)\b', re.I),
    # Extra patterns for memory leak hunting
    'cleanup':   re.compile(r'\b(CloseHandle|WSACleanup|closesocket|HeapFree|free|VirtualFree|DeleteCriticalSection|GlobalFree)\b'),
    'socket':    re.compile(r'\b(socket|connect|send|recv|bind|listen|closesocket|WSAStartup|WSACleanup|getaddrinfo|gethostbyname|ioctlsocket|select)\b'),
    'network':   re.compile(r'(6500|6515|3783|29900|gamespy|openspy|master\.gamespy)', re.I),
}

def load_index(filepath, no_cache=False):
    cache_path = str(Path(filepath).with_suffix('.diff_index.json'))
    if not no_cache and os.path.exists(cache_path):
        if os.path.getmtime(cache_path) > os.path.getmtime(filepath):
            print(f"  [cache] {cache_path}")
            with open(cache_path) as f:
                return json.load(f)
    print(f"  [warn] No cache found for {filepath}")
    print(f"         Run ds2_differ.py first to build the index cache")
    return {}

def read_func(path, offset, size, cap=65536):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(min(size, cap)).decode('utf-8', errors='replace')

def norm(t):
    t = re.sub(r'0x[0-9a-fA-F]+', 'HEX', t)
    t = re.sub(r'\bFUN_[0-9a-fA-F]+\b', 'FUN', t)
    t = re.sub(r'\bDAT_[0-9a-fA-F]+\b', 'DAT', t)
    t = re.sub(r'\bLAB_[0-9a-fA-F]+\b', 'LAB', t)
    t = re.sub(r'\b\d+\b', 'NUM', t)
    t = re.sub(r'//.*$', '', t, flags=re.MULTILINE)
    return re.sub(r'\s+', ' ', t).strip().lower()

def sim(a, b):
    na, nb = norm(a), norm(b)
    if not na and not nb: return 1.0
    if not na or not nb:  return 0.0
    fn = difflib.SequenceMatcher(None, na, nb)
    return fn.ratio() if len(na)+len(nb) < 20000 else fn.quick_ratio()

def detect(t, extra_cats=None):
    cats = {k for k, p in CATS.items() if p.search(t)}
    return list(cats)

def main():
    ap = argparse.ArgumentParser(description='DS2 Diff Category Filter')
    ap.add_argument('file_a')
    ap.add_argument('file_b')
    ap.add_argument('--cats', nargs='+', default=['threading', 'memory', 'cleanup', 'socket'],
                    help='Categories to filter (default: threading memory cleanup socket)')
    ap.add_argument('--status', default='changed',
                    choices=['changed', 'added', 'removed', 'all'],
                    help='Filter by status (default: changed)')
    ap.add_argument('--output', default='ds2_filtered.json')
    ap.add_argument('--no-cache', action='store_true')
    ap.add_argument('--show-body', action='store_true',
                    help='Include function body snippets in output')
    args = ap.parse_args()

    for f in [args.file_a, args.file_b]:
        if not os.path.exists(f):
            print(f"ERROR: file not found: {f}")
            sys.exit(1)

    print(f"\n{'='*56}")
    print(f"  DS2 CATEGORY FILTER")
    print(f"  Categories : {', '.join(args.cats)}")
    print(f"  Status     : {args.status}")
    print(f"{'='*56}\n")

    print("[1/2] Loading indexes...")
    ia = load_index(args.file_a, args.no_cache)
    ib = load_index(args.file_b, args.no_cache)

    if not ia or not ib:
        sys.exit(1)

    print(f"[2/2] Filtering {len(set(ia)|set(ib)):,} functions...")

    target_cats = set(args.cats)
    results = []
    funcs = sorted(set(ia) | set(ib))

    for name in funcs:
        in_a, in_b = name in ia, name in ib

        if in_a and in_b:
            ta = read_func(args.file_a, ia[name]['offset'], ia[name]['size'])
            tb = read_func(args.file_b, ib[name]['offset'], ib[name]['size'])
            sc = sim(ta, tb)
            status = 'identical' if sc >= 0.99 else 'changed'
            cats = list(set(detect(ta)) | set(detect(tb)))
            sa, sb = ia[name]['size'], ib[name]['size']
        elif in_a:
            ta = read_func(args.file_a, ia[name]['offset'], ia[name]['size'])
            tb = ''
            sc = 0.0
            cats = detect(ta)
            status = 'removed'
            sa, sb = ia[name]['size'], 0
        else:
            ta = ''
            tb = read_func(args.file_b, ib[name]['offset'], ib[name]['size'])
            sc = 0.0
            cats = detect(tb)
            status = 'added'
            sa, sb = 0, ib[name]['size']

        # Apply filters
        if args.status != 'all' and status != args.status:
            continue
        if not target_cats.intersection(set(cats)):
            continue

        entry = {
            'name': name,
            'status': status,
            'similarity': round(sc * 100, 1),
            'categories': cats,
            'size_a': sa,
            'size_b': sb,
            'matched_cats': list(target_cats.intersection(set(cats))),
        }

        # Optionally include snippets for manual review
        if args.show_body:
            # Show lines containing cleanup/socket calls
            leak_pat = re.compile(r'\b(CloseHandle|WSACleanup|closesocket|HeapFree|free|VirtualFree|CreateThread|socket|connect)\b')
            if ta:
                entry['body_a_hits'] = [l.strip() for l in ta.splitlines() if leak_pat.search(l)][:20]
            if tb:
                entry['body_b_hits'] = [l.strip() for l in tb.splitlines() if leak_pat.search(l)][:20]

        results.append(entry)

    # Sort by similarity ascending (most changed first)
    results.sort(key=lambda x: x['similarity'])

    print(f"\n  Found {len(results)} matching functions\n")

    # Print summary to console
    print(f"  {'FUNCTION':<45} {'STATUS':<10} {'SIM':>5}  CATEGORIES")
    print(f"  {'-'*80}")
    for r in results:
        cats_str = ', '.join(r['matched_cats'])
        print(f"  {r['name']:<45} {r['status']:<10} {r['similarity']:>4.0f}%  {cats_str}")

    # Save full results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  [json] {args.output}  ({len(results)} functions)")
    print(f"\n  Tip: run with --show-body to see cleanup call diffs")
    print(f"  Tip: look for functions where body_a_hits has CloseHandle/closesocket")
    print(f"       but body_b_hits does NOT — those are your leak candidates\n")

if __name__ == '__main__':
    main()