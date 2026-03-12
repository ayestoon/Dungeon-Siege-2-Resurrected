#!/usr/bin/env python3
"""
DS2 Binary Survey Tool
======================
Step 1 of the AI analysis pipeline.
Runs LOCALLY — zero API cost.

What it does:
  - Scans all your DS2 C exports
  - Identifies already-named functions (FID hits, CRT, known patterns)
  - Finds unnamed fun_ functions that appear in diffs (priority targets)
  - Groups functions by address range (helps identify subsystems)
  - Estimates API cost before you spend anything
  - Produces a prioritized work queue for the AI analysis step

Usage:
  # Point it at a folder containing your .c exports and .diff_index.json files
  python ds2_survey.py --dir "C:/ds2_exports"

  # Or specify files directly
  python ds2_survey.py --files v22.c reloaded_v23.c killah_v23.c steam_v23.c

  # After running, review ds2_survey_report.html before running AI analysis
"""

import os
import re
import json
import argparse
import time
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime


# ── Known name patterns ────────────────────────────────────────────────────────

# These are already identified — skip for AI analysis
KNOWN_PATTERNS = [
    # MSVC CRT internals
    (re.compile(r'^_{2,3}'), 'crt'),
    (re.compile(r'^_[a-z]'), 'crt_internal'),
    # Exception handling
    (re.compile(r'^catch_'), 'exception_handler'),
    (re.compile(r'^__except'), 'exception_handler'),
    # FID-resolved (Ghidra named these automatically)
    (re.compile(r'^fid_conflict_'), 'fid_conflict'),
    # Thunks
    (re.compile(r'^thunk_'), 'thunk'),
    # Entry points
    (re.compile(r'^entry$'), 'entry'),
    (re.compile(r'^winmain', re.I), 'entry'),
    # Known DS2 patterns from symbol names
    (re.compile(r'UIFrontend', re.I), 'ds2_ui'),
    (re.compile(r'SiegeNode|NodeGraph', re.I), 'ds2_node'),
    (re.compile(r'TankFile|SiegeTank', re.I), 'ds2_tank'),
    (re.compile(r'siegelet', re.I), 'ds2_siegelet'),
    (re.compile(r'gpbstring', re.I), 'ds2_string'),
    (re.compile(r'scan_tree', re.I), 'ds2_filetree'),
    # Standard lib
    (re.compile(r'^std_|^_std'), 'stdlib'),
    (re.compile(r'locale|setlocale', re.I), 'locale'),
    (re.compile(r'wsastartup', re.I), 'winsock'),
]

# DS2 address range map — rough subsystem boundaries
# These are estimates based on what we've seen in the diffs
# Will be refined as we learn more
ADDRESS_RANGES = [
    (0x00400000, 0x00420000, 'startup_init'),
    (0x00420000, 0x00500000, 'core_engine_low'),
    (0x00500000, 0x00600000, 'core_engine_mid'),
    (0x00600000, 0x00700000, 'game_logic_a'),       # 0x006x — critical zone
    (0x00700000, 0x00800000, 'game_logic_b'),
    (0x00800000, 0x00900000, 'game_logic_c'),
    (0x00900000, 0x00A00000, 'game_logic_d'),
    (0x00A00000, 0x00B00000, 'game_logic_e'),       # 0x009e-0x00a0 — rewritten subsystem
    (0x00B00000, 0x00C00000, 'expansion_bw'),       # BW-specific code likely here
    (0x00C00000, 0x00D00000, 'resources_ui'),
    (0x00D00000, 0x01000000, 'crt_stdlib'),
    (0x01000000, 0x01200000, 'plugin_layer'),       # 0x011x addresses
    (0x01800000, 0x01900000, 'thunk_layer'),        # KILLAH's injected thunks
]

# DS2-specific call patterns to detect
INTERESTING_CALLS = {
    'memory':    re.compile(r'\b(VirtualAlloc|VirtualFree|HeapAlloc|HeapFree|malloc|free)\b'),
    'hvci':      re.compile(r'\b(VirtualProtect|PAGE_EXECUTE|MEM_COMMIT)\b'),
    'directx':   re.compile(r'\b(IDirect3D|Direct3DCreate|CreateDevice)\b', re.I),
    'audio':     re.compile(r'\b(AIL_|miles|mss32|DirectSound|waveOut)\b', re.I),
    'tank':      re.compile(r'\b(tank|TankFile|siegelet|SiegeTank)\b', re.I),
    'node':      re.compile(r'\b(SiegeNode|NodeGraph|sno_)\b', re.I),
    'timing':    re.compile(r'\b(QueryPerformanceCounter|timeGetTime|GetTickCount|Sleep)\b', re.I),
    'threading': re.compile(r'\b(CreateThread|WaitForSingle|EnterCriticalSection|CRITICAL_SECTION)\b'),
    'fileio':    re.compile(r'\b(CreateFile|ReadFile|WriteFile|fopen)\b'),
    'input':     re.compile(r'\b(GetCursorPos|SetCursorPos|mouse_event|DirectInput|GetKeyState)\b', re.I),
    'network':   re.compile(r'\b(WSA|socket|connect|send|recv|bind|listen)\b', re.I),
    'registry':  re.compile(r'\b(RegOpenKey|RegQueryValue|RegSetValue|HKEY)\b', re.I),
    'cdcheck':   re.compile(r'\b(GetDriveType|GetVolumeInfo|DeviceIoControl|IOCTL)\b', re.I),
}


# ── Index loader ───────────────────────────────────────────────────────────────

def load_index(c_file):
    """Load or build index for a C export file."""
    cache = str(Path(c_file).with_suffix('.diff_index.json'))
    if os.path.exists(cache):
        mod_c = os.path.getmtime(c_file)
        mod_cache = os.path.getmtime(cache)
        if mod_cache > mod_c:
            with open(cache) as f:
                idx = json.load(f)
            print(f"  [cache] {Path(c_file).name}: {len(idx):,} functions")
            return idx

    print(f"  [scan]  {Path(c_file).name} ({os.path.getsize(c_file)/1024/1024:.0f} MB)...")
    from ds2_differ import build_index
    return build_index(c_file, cache)


def read_func(path, offset, size, cap=32768):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(min(size, cap)).decode('utf-8', errors='replace')


# ── Function classifier ────────────────────────────────────────────────────────

def classify_function(name, body=''):
    """Return (category, known) where known=True means skip AI analysis."""
    name_lower = name.lower()

    for pat, cat in KNOWN_PATTERNS:
        if pat.search(name):
            return cat, True

    # Pure fun_ address — unknown, candidate for AI
    if re.match(r'^fun_[0-9a-f]+$', name_lower):
        cats = [c for c, p in INTERESTING_CALLS.items() if p.search(body)]
        return ('unknown_' + '_'.join(cats[:2])) if cats else 'unknown', False

    # Has a real name but not in known patterns — partially identified
    return 'named_unknown', True  # don't re-analyze named functions


def addr_from_name(name):
    """Extract address from fun_XXXXXXXX style names."""
    m = re.match(r'fun_([0-9a-fA-F]+)', name)
    return int(m.group(1), 16) if m else 0


def get_range(addr):
    for start, end, label in ADDRESS_RANGES:
        if start <= addr < end:
            return label
    return 'unknown_range'


# ── Diff loader ────────────────────────────────────────────────────────────────

def load_diff_report(html_file):
    """Extract function diff data from an existing HTML report."""
    with open(html_file, encoding='utf-8') as f:
        content = f.read()
    rows = re.findall(
        r'data-status="(\w+)" data-pri="(\w+)" data-score="([\d.]+)" data-name="([^"]+)"',
        content
    )
    return {r[3]: {'status': r[0], 'priority': r[1], 'score': float(r[2])} for r in rows}


# ── Main survey ────────────────────────────────────────────────────────────────

def survey(files, diff_reports=None):
    print(f"\n{'='*60}")
    print(f"  DS2 BINARY SURVEY")
    print(f"{'='*60}\n")

    # Load all indexes
    indexes = {}
    for f in files:
        if not os.path.exists(f):
            print(f"  [skip] Not found: {f}")
            continue
        label = Path(f).stem
        indexes[label] = {'file': f, 'index': load_index(f)}

    if not indexes:
        print("No valid files found.")
        return

    # Load diff reports if provided
    diffs = {}
    if diff_reports:
        for dr in diff_reports:
            if os.path.exists(dr):
                label = Path(dr).stem
                diffs[label] = load_diff_report(dr)
                print(f"  [diff] Loaded {label}: {len(diffs[label]):,} entries")

    print(f"\n  Versions loaded: {list(indexes.keys())}")

    # Build master function list across all versions
    print(f"\n[1/4] Building master function list...")
    all_funcs = defaultdict(dict)  # name -> {version: {offset, size}}
    for label, data in indexes.items():
        for name, info in data['index'].items():
            all_funcs[name][label] = info

    print(f"  Total unique functions: {len(all_funcs):,}")

    # Classify all functions
    print(f"\n[2/4] Classifying functions...")
    classifications = {}
    range_counts = Counter()
    cat_counts = Counter()
    unknown_count = 0

    # Load function bodies for unknown functions (sample first version that has it)
    for name, versions in all_funcs.items():
        body = ''
        # Try to get body from first available version
        for label, info in versions.items():
            try:
                body = read_func(indexes[label]['file'], info['offset'], info['size'])
                break
            except Exception:
                continue

        cat, known = classify_function(name, body)
        addr = addr_from_name(name)
        rng = get_range(addr)
        cats_found = [c for c, p in INTERESTING_CALLS.items() if p.search(body)] if not known else []

        classifications[name] = {
            'category': cat,
            'known': known,
            'address': addr,
            'range': rng,
            'interesting_cats': cats_found,
            'versions': list(versions.keys()),
            'size': max(v.get('size', 0) for v in versions.values()),
        }

        if not known:
            unknown_count += 1
        range_counts[rng] += 1
        cat_counts[cat] += 1

    print(f"  Known/named: {len(all_funcs) - unknown_count:,}")
    print(f"  Unknown (AI candidates): {unknown_count:,}")

    # Priority queue — functions most worth analyzing
    print(f"\n[3/4] Building priority queue...")

    # Gather diff info
    diff_lookup = {}
    for diff_label, diff_data in diffs.items():
        for fname, info in diff_data.items():
            if fname not in diff_lookup or info['score'] < diff_lookup[fname]['score']:
                diff_lookup[fname] = {**info, 'diff': diff_label}

    priority_queue = []
    for name, info in classifications.items():
        if info['known']:
            continue

        score = 100  # base priority score

        # Boost for diff presence
        if name in diff_lookup:
            d = diff_lookup[name]
            if d['priority'] == 'CRITICAL':
                score += 1000
            elif d['priority'] == 'HIGH':
                score += 500
            elif d['priority'] == 'MEDIUM':
                score += 100
            # Lower similarity = more changed = higher priority
            score += int((1.0 - d['score']) * 200)

        # Boost for interesting call patterns
        score += len(info['interesting_cats']) * 50

        # Boost for being in the critical address zones we identified
        if info['range'] in ('game_logic_a', 'game_logic_b'):
            score += 200
        if info['range'] == 'game_logic_e':  # the rewritten 0x009e-0x00a0 block
            score += 150

        # Penalize tiny functions (likely stubs/trampolines)
        if info['size'] < 50:
            score -= 200

        diff_info = diff_lookup.get(name, {})
        priority_queue.append({
            'name': name,
            'priority_score': score,
            'address': info['address'],
            'range': info['range'],
            'interesting_cats': info['interesting_cats'],
            'size': info['size'],
            'versions_present': info['versions'],
            'diff_status': diff_info.get('status', 'not_in_diff'),
            'diff_priority': diff_info.get('priority', '—'),
            'diff_score': diff_info.get('score', 1.0),
            'diff_label': diff_info.get('diff', '—'),
        })

    priority_queue.sort(key=lambda x: -x['priority_score'])

    # Cost estimate
    top_100 = [f for f in priority_queue if f['priority_score'] > 200][:100]
    top_500 = [f for f in priority_queue if f['priority_score'] > 100][:500]
    avg_size = 200  # avg tokens per function (input)
    overhead = 300  # system prompt + output per call

    cost_100  = (len(top_100)  * (avg_size + overhead) / 1_000_000) * 3.0
    cost_500  = (len(top_500)  * (avg_size + overhead) / 1_000_000) * 3.0
    cost_full = (len(priority_queue) * (avg_size + overhead) / 1_000_000) * 3.0

    print(f"  Priority queue: {len(priority_queue):,} candidates")
    print(f"  Top 100 (CRITICAL/HIGH): ~${cost_100:.2f} USD")
    print(f"  Top 500 (recommended):   ~${cost_500:.2f} USD")
    print(f"  Full unknown set:        ~${cost_full:.2f} USD")

    # Generate report
    print(f"\n[4/4] Generating report...")
    _make_report(indexes, classifications, priority_queue, range_counts,
                 cat_counts, diff_lookup, cost_100, cost_500, cost_full)


# ── HTML Report ────────────────────────────────────────────────────────────────

def _make_report(indexes, classifications, priority_queue, range_counts,
                 cat_counts, diff_lookup, cost_100, cost_500, cost_full):

    version_list = list(indexes.keys())

    # Range breakdown table
    range_rows = ''.join(
        f'<tr><td class="rng">{r}</td>'
        f'<td style="color:var(--orange);font-weight:700">{c:,}</td>'
        f'<td><div class="bar-wrap"><div class="bar" style="width:{min(100,c//20)}%;background:var(--gold)"></div></div></td></tr>'
        for r, c in sorted(range_counts.items(), key=lambda x: -x[1])
    )

    # Top priority functions table
    func_rows = []
    for i, f in enumerate(priority_queue[:500]):
        cats = ' '.join(f'<span class="cat cat-{c}">{c}</span>' for c in f['interesting_cats'])
        vers = ' '.join(f'<span class="ver">{v}</span>' for v in f['versions_present'])
        score_col = '#e04040' if f['diff_priority'] == 'CRITICAL' else \
                    '#e08020' if f['diff_priority'] == 'HIGH' else \
                    '#d4b820' if f['diff_priority'] == 'MEDIUM' else '#7a6840'
        sim_pct = int(f['diff_score'] * 100)
        func_rows.append(
            f'<tr class="fr" data-range="{f["range"]}" data-pri="{f["diff_priority"]}">'
            f'<td style="color:var(--text-faint);font-size:10px">{i+1}</td>'
            f'<td class="fn">{f["name"]}</td>'
            f'<td style="color:{score_col};font-weight:700;font-size:11px">{f["diff_priority"]}</td>'
            f'<td style="color:var(--text-dim);font-size:11px">{f["range"]}</td>'
            f'<td>{cats}</td>'
            f'<td>{vers}</td>'
            f'<td style="color:var(--text-dim);font-size:11px">'
            f'{f["diff_status"]} {sim_pct}%</td>'
            f'<td style="color:var(--gold-dim);font-family:monospace;font-size:10px">'
            f'{f["priority_score"]}</td>'
            f'</tr>'
        )

    # Export priority queue as JSON for the AI analysis step
    queue_json = json.dumps([{
        'name': f['name'],
        'address': hex(f['address']),
        'range': f['range'],
        'categories': f['interesting_cats'],
        'diff_priority': f['diff_priority'],
        'diff_score': f['diff_score'],
        'priority_score': f['priority_score'],
    } for f in priority_queue[:500]], indent=2)

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>DS2 Binary Survey</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&family=Share+Tech+Mono&display=swap');
:root{{--bg:#070604;--bg1:#0c0a06;--bg2:#111008;--bg3:#181508;--border:#2a2010;--border2:#3a3018;
--gold:#c8a84b;--gold-dim:#6a5a28;--text:#c8b87a;--text-dim:#7a6840;--text-faint:#3a3018;
--red:#e04040;--orange:#e08020;--yellow:#d4b820;--blue:#4ab4d8;--green:#50b860;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:13px}}
.hdr{{background:linear-gradient(180deg,#1a1200,#0c0a06);border-bottom:1px solid var(--border);padding:20px 28px}}
.hdr h1{{font-family:'Cinzel',serif;color:var(--gold);font-size:22px;letter-spacing:3px}}
.sub{{color:var(--text-dim);font-size:12px;margin-top:4px}}
.main{{padding:22px 28px;max-width:1500px}}
h2{{font-family:'Cinzel',serif;color:var(--gold-dim);font-size:12px;letter-spacing:2px;
    margin:20px 0 10px;border-bottom:1px solid var(--border);padding-bottom:5px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:5px;
       padding:10px 18px;text-align:center;min-width:100px}}
.sv{{font-size:20px;font-weight:700}}
.sl{{color:var(--text-dim);font-size:10px;font-family:'Cinzel',serif;letter-spacing:1px;margin-top:2px}}
.cost-box{{background:var(--bg2);border:1px solid var(--border2);border-radius:5px;
           padding:14px 20px;margin-bottom:18px;font-size:12px;line-height:2}}
.cost-box .big{{color:var(--gold);font-size:18px;font-weight:700}}
.note{{background:var(--bg2);border-left:3px solid var(--gold);padding:10px 14px;
       margin:8px 0 14px;color:var(--text-dim);font-size:12px;line-height:1.7}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:var(--bg3);color:var(--gold-dim);padding:7px 10px;text-align:left;
    border-bottom:2px solid var(--border);font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px}}
td{{padding:5px 10px;border-bottom:1px solid var(--bg3);vertical-align:middle}}
tr:hover td{{background:var(--bg2)}}
.fr.hide{{display:none}}
.fn{{color:#e8d5a0;font-weight:700;word-break:break-all;max-width:300px;font-size:11px}}
.rng{{color:var(--text-dim);font-size:11px}}
.bar-wrap{{width:120px;height:6px;background:var(--bg3);border-radius:3px;
           overflow:hidden;display:inline-block;vertical-align:middle}}
.bar{{height:100%;border-radius:3px}}
.cat{{display:inline-block;font-size:10px;padding:1px 5px;border-radius:2px;margin:1px;white-space:nowrap}}
.cat-memory{{background:#1a0808;color:#e06060;border:1px solid #400808}}
.cat-hvci{{background:#200808;color:#ff5050;border:1px solid #600808}}
.cat-directx{{background:#081018;color:#60a0e0;border:1px solid #102040}}
.cat-audio{{background:#0a0818;color:#9060e0;border:1px solid #201040}}
.cat-tank{{background:#100808;color:#c06040;border:1px solid #301808}}
.cat-node{{background:#181008;color:#d08020;border:1px solid #402010}}
.cat-timing{{background:#081408;color:#40c060;border:1px solid #103010}}
.cat-threading{{background:#100a18;color:#b070d0;border:1px solid #281840}}
.cat-fileio{{background:#0a100a;color:#70b070;border:1px solid #183018}}
.cat-input{{background:#080a18;color:#60a0d0;border:1px solid #101840}}
.cat-network{{background:#081818;color:#40c0c0;border:1px solid #103030}}
.cat-cdcheck{{background:#181808;color:#c0c040;border:1px solid #303008}}
.cat-registry{{background:#100a08;color:#c08060;border:1px solid #301808}}
.ver{{display:inline-block;font-size:10px;padding:1px 6px;border-radius:2px;margin:1px;
      background:#0c1008;color:#60a040;border:1px solid #182010;white-space:nowrap}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}}
.fb{{background:var(--bg2);border:1px solid var(--border2);color:var(--text-dim);
     padding:5px 13px;border-radius:3px;cursor:pointer;font-family:'Cinzel',serif;
     font-size:10px;letter-spacing:1px}}
.fb.on{{background:#2a1f0a;border-color:var(--gold);color:var(--gold)}}
.srch{{background:var(--bg2);border:1px solid var(--border2);color:var(--text);
       padding:6px 12px;border-radius:3px;font-family:'Share Tech Mono',monospace;
       font-size:12px;width:220px;outline:none}}
.cnt{{color:var(--text-faint);font-size:11px;margin-left:auto}}
.json-box{{background:var(--bg2);border:1px solid var(--border);border-radius:4px;
           padding:14px;font-size:11px;color:var(--text-dim);overflow:auto;
           max-height:300px;white-space:pre;margin-top:8px}}
.copy-btn{{background:#2a1f0a;border:1px solid var(--gold-dim);color:var(--gold);
           padding:6px 14px;border-radius:3px;cursor:pointer;font-family:'Cinzel',serif;
           font-size:10px;letter-spacing:1px;margin-bottom:8px}}
.copy-btn:hover{{border-color:var(--gold)}}
</style></head><body>
<div class="hdr">
  <h1>⚔ DS2 BINARY SURVEY</h1>
  <div class="sub">Pre-analysis report — {datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;|&nbsp;
  Versions: {", ".join(version_list)}</div>
</div>
<div class="main">

<h2>VERSIONS LOADED</h2>
<div class="stats">
  {''.join(f'<div class="stat"><div class="sv" style="color:var(--blue)">{len(d["index"]):,}</div><div class="sl">{label.upper()}</div></div>' for label, d in indexes.items())}
</div>

<h2>FUNCTION BREAKDOWN</h2>
<div class="stats">
  <div class="stat"><div class="sv" style="color:var(--text)">{len(classifications):,}</div><div class="sl">TOTAL UNIQUE</div></div>
  <div class="stat"><div class="sv" style="color:var(--green)">{sum(1 for c in classifications.values() if c["known"]):,}</div><div class="sl">IDENTIFIED</div></div>
  <div class="stat"><div class="sv" style="color:var(--orange)">{len(priority_queue):,}</div><div class="sl">AI CANDIDATES</div></div>
  <div class="stat"><div class="sv" style="color:var(--red)">{sum(1 for f in priority_queue if f["diff_priority"]=="CRITICAL")}</div><div class="sl">CRITICAL</div></div>
  <div class="stat"><div class="sv" style="color:var(--orange)">{sum(1 for f in priority_queue if f["diff_priority"]=="HIGH")}</div><div class="sl">HIGH</div></div>
</div>

<h2>ESTIMATED API COST (Claude Sonnet)</h2>
<div class="cost-box">
  Top 100 functions (CRITICAL + HIGH priority): &nbsp;<span class="big">${cost_100:.2f}</span> USD<br>
  Top 500 functions (recommended sweep): &nbsp;<span class="big">${cost_500:.2f}</span> USD<br>
  Full unknown set ({len(priority_queue):,} functions): &nbsp;<span class="big">${cost_full:.2f}</span> USD<br>
  <span style="color:var(--text-faint);font-size:11px">
  Estimates based on ~500 tokens/call at Sonnet pricing. Actual cost may vary.
  FID pass first will reduce unknown count significantly.
  </span>
</div>

<h2>ADDRESS RANGE BREAKDOWN</h2>
<div class="note">
  Each range corresponds to a likely subsystem. Ranges with many unknown functions
  are the highest value targets for AI analysis. The 0x006x and 0x009e-0x00a0
  ranges are already confirmed high-interest from diff analysis.
</div>
<table style="margin-bottom:18px">
  <tr><th>ADDRESS RANGE / SUBSYSTEM</th><th>FUNCTION COUNT</th><th>DENSITY</th></tr>
  {range_rows}
</table>

<h2>PRIORITY QUEUE — TOP 500 AI ANALYSIS TARGETS</h2>
<div class="note">
  Ranked by: diff priority × similarity change × interesting call patterns × address range.
  Run FID analysis in Ghidra first — it will auto-identify many of these for free.
  Then feed this list to ds2_analyze.py for AI-assisted identification.
</div>
<div class="filters">
  <button class="fb on" onclick="fs('all')">ALL</button>
  <button class="fb" onclick="fs('CRITICAL')">CRITICAL</button>
  <button class="fb" onclick="fs('HIGH')">HIGH</button>
  <button class="fb" onclick="fs('MEDIUM')">MEDIUM</button>
  <input class="srch" type="text" placeholder="Search function name..." oninput="fq(this.value)">
  <span class="cnt" id="ci">{min(500,len(priority_queue)):,} functions</span>
</div>
<table>
  <thead><tr>
    <th>#</th><th>FUNCTION</th><th>DIFF PRI</th><th>RANGE</th>
    <th>CALL PATTERNS</th><th>VERSIONS</th><th>DIFF STATUS</th><th>SCORE</th>
  </tr></thead>
  <tbody id="tb">
  {''.join(func_rows)}
  </tbody>
</table>

<h2>NEXT STEPS</h2>
<div class="note" style="line-height:2">
  <strong style="color:var(--gold)">1. Ghidra FID pass</strong> — Window → Analysis → One Shot → Function ID
  &nbsp;→ will auto-name CRT/STL functions, reducing unknown count significantly<br>
  <strong style="color:var(--gold)">2. Re-run this survey</strong> after FID to get updated cost estimate<br>
  <strong style="color:var(--gold)">3. Export priority queue JSON</strong> (button below) — input for ds2_analyze.py<br>
  <strong style="color:var(--gold)">4. Run ds2_analyze.py</strong> with your Anthropic API key — processes queue overnight<br>
  <strong style="color:var(--gold)">5. Results feed back into Ghidra</strong> as function comments via script
</div>

<h2>PRIORITY QUEUE JSON — INPUT FOR ds2_analyze.py</h2>
<button class="copy-btn" onclick="copyJson()">COPY TO CLIPBOARD</button>
<div class="json-box" id="jb">{queue_json}</div>

</div>
<script>
let cP='all',cQ='';
function upd(){{
  let v=0;
  document.querySelectorAll('.fr').forEach(r=>{{
    const ok=(cP==='all'||r.dataset.pri===cP)&&(!cQ||r.dataset.range.includes(cQ)||r.cells[1].textContent.includes(cQ));
    r.classList.toggle('hide',!ok);if(ok)v++;
  }});
  document.getElementById('ci').textContent=v.toLocaleString()+' functions';
}}
function fs(p){{cP=p;document.querySelectorAll('.fb').forEach(b=>b.classList.toggle('on',b.textContent===p||(p==='all'&&b.textContent==='ALL')));upd();}}
function fq(v){{cQ=v.toLowerCase();upd();}}
function copyJson(){{
  navigator.clipboard.writeText(document.getElementById('jb').textContent);
  document.querySelector('.copy-btn').textContent='COPIED!';
  setTimeout(()=>document.querySelector('.copy-btn').textContent='COPY TO CLIPBOARD',2000);
}}
</script>
</body></html>'''

    out = 'ds2_survey_report.html'
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    out_json = 'ds2_priority_queue.json'
    with open(out_json, 'w') as f:
        json.dump([{
            'name': f['name'],
            'address': hex(f['address']),
            'range': f['range'],
            'categories': f['interesting_cats'],
            'diff_priority': f['diff_priority'],
            'diff_score': f['diff_score'],
            'priority_score': f['priority_score'],
        } for f in priority_queue[:500]], f, indent=2)

    print(f"\n  [html] {out}")
    print(f"  [json] {out_json}  ← feed this to ds2_analyze.py")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DS2 Binary Survey — pre-AI analysis pass')
    ap.add_argument('--dir',   default=None, help='Folder containing .c exports')
    ap.add_argument('--files', nargs='+',    help='Explicit list of .c export files')
    ap.add_argument('--diffs', nargs='+',    help='Existing diff HTML reports to load')
    args = ap.parse_args()

    files = []
    if args.files:
        files = args.files
    elif args.dir:
        d = Path(args.dir)
        files = [str(f) for f in sorted(d.glob('*.c'))]
        if not files:
            # Try looking for cached indexes without .c files
            files = [str(f.with_suffix('.c')) for f in sorted(d.glob('*.diff_index.json'))]

    if not files:
        print("No files specified. Use --dir or --files.")
        print("Example: python ds2_survey.py --dir C:/ds2_exports")
        print("Example: python ds2_survey.py --files v22.c reloaded.c killah.c")
        return

    diffs = args.diffs or []

    # Also auto-detect diff reports in same folder as files
    for f in files:
        folder = Path(f).parent
        for html in folder.glob('*diff*report*.html'):
            if str(html) not in diffs:
                diffs.append(str(html))
                print(f"  [auto] Found diff report: {html.name}")

    survey(files, diffs)


if __name__ == '__main__':
    main()
