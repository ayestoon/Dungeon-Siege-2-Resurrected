#!/usr/bin/env python3
"""
DS2 Network & GameSpy Dependency Scanner
==========================================
Scans DS2 C exports to find:
  - All DLL imports and which functions use them
  - GameSpy SDK references
  - Hardcoded server addresses, URLs, ports
  - WinHTTP / WinINet / Winsock usage
  - Functions that would need patching for multiplayer revival

Usage:
    python ds2_netscanner.py --dir "C:/ds2_exports"
    python ds2_netscanner.py --files bw2.3.c killah.c

Output:
    ds2_network_report.html
    ds2_network_patch_targets.json  -- functions needing server address patches
"""

import os
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


# ── Detection patterns ─────────────────────────────────────────────────────────

# GameSpy SDK components
GAMESPY_PATTERNS = {
    'gamespy_core':    re.compile(r'\b(GameSpy|gspy|GOA|goa_)\b', re.I),
    'gamespy_gt2':     re.compile(r'\b(gt2|GT2)\b'),
    'gamespy_peer':    re.compile(r'\b(peerSB|PeerSB|peer_)\b', re.I),
    'gamespy_qr2':     re.compile(r'\b(qr2|QR2|QueryReport)\b', re.I),
    'gamespy_sb':      re.compile(r'\b(ServerBrows|serverBrows|sbEnumerate|sbCreate)\b', re.I),
    'gamespy_gp':      re.compile(r'\b(gpConnect|gpSearch|gpProfile|GPResult)\b', re.I),
    'gamespy_natneg':  re.compile(r'\b(NNBegin|NNCancel|natneg|NATNEG)\b', re.I),
    'gamespy_stats':   re.compile(r'\b(statsConnect|StatsNewGame|PersCreate)\b', re.I),
    'gamespy_voice':   re.compile(r'\b(VoiceInit|voice2|GVDevice)\b', re.I),
    'gamespy_sake':    re.compile(r'\b(sakeInit|SAKEField|sake)\b', re.I),
}

# Network DLL imports
DLL_PATTERNS = {
    'winhttp':     re.compile(r'\b(WinHttpOpen|WinHttpConnect|WinHttpSendRequest|WinHttpReceiveResponse|WinHttpReadData|WinHttpQueryHeaders|winhttp)\b', re.I),
    'wininet':     re.compile(r'\b(InternetOpen|InternetConnect|HttpOpenRequest|HttpSendRequest|InternetReadFile|wininet)\b', re.I),
    'winsock':     re.compile(r'\b(WSAStartup|WSACleanup|socket|connect|send|recv|bind|listen|select|closesocket|getaddrinfo|gethostbyname)\b'),
    'directplay':  re.compile(r'\b(IDirectPlay|DirectPlayCreate|DPID|dpid|DPlay)\b', re.I),
    'dplay8':      re.compile(r'\b(IDirectPlay8|DirectPlay8Create|DPN_)\b', re.I),
}

# Hardcoded server/URL strings
STRING_PATTERNS = {
    'gamespy_domain':  re.compile(r'"[^"]*gamespy\.[a-z]+"', re.I),
    'gamespy_ms':      re.compile(r'"[^"]*\.available\.gamespy\.[a-z]+"', re.I),
    'gs_domain':       re.compile(r'"[^"]*\.gs\.com"', re.I),
    'url':             re.compile(r'"https?://[^"]+"', re.I),
    'hostname':        re.compile(r'"[a-z0-9][a-z0-9\-]*\.[a-z]{2,}\.[a-z]{2,}"', re.I),
    'ip_address':      re.compile(r'"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"'),
    'gamespy_ports':   re.compile(r'\b(27900|27901|28910|29900|29901|6500|6515|3783)\b'),
}

# Known GameSpy master server ports and what they do
GAMESPY_PORTS = {
    27900: 'Master Server (game list)',
    27901: 'Master Server (alternate)',
    28910: 'NAT Negotiation',
    29900: 'Presence & Messaging (login)',
    29901: 'Presence Search',
    6500:  'Query port (server browser)',
    6515:  'CD key verification',
    3783:  'Voice chat',
}

# Known replacement servers for GameSpy revival
REPLACEMENT_SERVERS = {
    'openspy':     'na.openspy.net / eu.openspy.net',
    'gsmaster':    'See: github.com/vienneau/gamespy-master',
    'retrospy':    'See: retrospy.net',
    'multiplay':   'Some titles use multiplay.co.uk alternatives',
}

# Function body reader
def read_func_at(path, offset, size, cap=65536):
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(min(size, cap)).decode('utf-8', errors='replace')


# Load index from cache
def load_index(c_file):
    cache = str(Path(c_file).with_suffix('.diff_index.json'))
    if os.path.exists(cache):
        if os.path.getmtime(cache) > os.path.getmtime(c_file):
            with open(cache) as f:
                return json.load(f)
    # Fall back to inline scanner
    print(f"  [warn] No cache for {Path(c_file).name} — run ds2_differ.py first")
    return {}


def scan_file(c_file, index):
    """Scan a C export for all network/gamespy references."""
    results = {
        'gamespy': defaultdict(list),   # component -> [func_name, ...]
        'dlls':    defaultdict(list),
        'strings': defaultdict(list),   # pattern -> [(func_name, match), ...]
        'ports':   defaultdict(list),
        'patch_targets': [],            # functions that need server addr patches
    }

    filesize = os.path.getsize(c_file)
    print(f"  Scanning {Path(c_file).name} ({filesize/1024/1024:.0f} MB, {len(index):,} functions)...")

    for func_name, info in index.items():
        body = read_func_at(c_file, info['offset'], info['size'])

        hits = []

        # GameSpy checks
        for comp, pat in GAMESPY_PATTERNS.items():
            if pat.search(body):
                results['gamespy'][comp].append(func_name)
                hits.append(f'gamespy:{comp}')

        # DLL checks
        for dll, pat in DLL_PATTERNS.items():
            if pat.search(body):
                results['dlls'][dll].append(func_name)
                hits.append(f'dll:{dll}')

        # String checks
        for stype, pat in STRING_PATTERNS.items():
            matches = pat.findall(body)
            if matches:
                for m in matches:
                    results['strings'][stype].append((func_name, m[:80]))
                hits.append(f'string:{stype}')

        # Port checks
        for port, desc in GAMESPY_PORTS.items():
            if str(port) in body:
                results['ports'][port].append(func_name)
                hits.append(f'port:{port}')

        # Mark as patch target if it has server strings or GameSpy refs
        if hits and any('string' in h or 'gamespy' in h or 'port' in h for h in hits):
            addr = int(re.search(r'[0-9a-fA-F]+$', func_name.replace('fun_','')).group() 
                      if re.search(r'fun_([0-9a-fA-F]+)', func_name) else '0', 16) \
                  if 'fun_' in func_name else 0
            results['patch_targets'].append({
                'function': func_name,
                'address': hex(addr) if addr else '?',
                'hits': hits,
                'size': info['size'],
            })

    total_hits = sum(len(v) for v in results['gamespy'].values()) + \
                 sum(len(v) for v in results['dlls'].values())
    print(f"    GameSpy refs: {sum(len(v) for v in results['gamespy'].values())}")
    print(f"    Network DLL refs: {sum(len(v) for v in results['dlls'].values())}")
    print(f"    Hardcoded strings: {sum(len(v) for v in results['strings'].values())}")
    print(f"    Port references: {sum(len(v) for v in results['ports'].values())}")
    print(f"    Patch targets: {len(results['patch_targets'])}")

    return results


def make_report(all_results, output='ds2_network_report.html'):
    """Generate HTML report of all network findings."""

    # Collect all unique patch targets across versions
    all_targets = {}
    for version, results in all_results.items():
        for pt in results['patch_targets']:
            name = pt['function']
            if name not in all_targets:
                all_targets[name] = {'function': name, 'address': pt['address'],
                                     'hits': pt['hits'], 'versions': []}
            if version not in all_targets[name]['versions']:
                all_targets[name]['versions'].append(version)

    # GameSpy component summary across all versions
    gs_summary = defaultdict(set)
    dll_summary = defaultdict(set)
    string_summary = defaultdict(list)
    port_summary = defaultdict(set)

    for version, results in all_results.items():
        for comp, funcs in results['gamespy'].items():
            for f in funcs: gs_summary[comp].add(f)
        for dll, funcs in results['dlls'].items():
            for f in funcs: dll_summary[dll].add(f)
        for stype, pairs in results['strings'].items():
            for func, match in pairs:
                if match not in [m for _, m in string_summary[stype]]:
                    string_summary[stype].append((func, match))
        for port, funcs in results['ports'].items():
            for f in funcs: port_summary[port].add(f)

    # Build HTML sections
    gs_rows = ''
    for comp, funcs in sorted(gs_summary.items(), key=lambda x: -len(x[1])):
        func_list = ', '.join(sorted(funcs)[:5])
        if len(funcs) > 5: func_list += f' +{len(funcs)-5} more'
        gs_rows += f'<tr><td class="cat cat-gs">{comp}</td><td style="color:var(--orange)">{len(funcs)}</td><td style="color:var(--text-dim);font-size:11px">{func_list}</td></tr>'

    dll_rows = ''
    for dll, funcs in sorted(dll_summary.items(), key=lambda x: -len(x[1])):
        func_list = ', '.join(sorted(funcs)[:5])
        if len(funcs) > 5: func_list += f' +{len(funcs)-5} more'
        color = '#ff5050' if dll in ('winhttp','wininet') else '#60a0e0'
        dll_rows += f'<tr><td style="color:{color};font-weight:700">{dll}</td><td style="color:var(--orange)">{len(funcs)}</td><td style="color:var(--text-dim);font-size:11px">{func_list}</td></tr>'

    string_rows = ''
    seen_strings = set()
    for stype, pairs in sorted(string_summary.items()):
        for func, match in pairs[:10]:
            if match in seen_strings: continue
            seen_strings.add(match)
            color = '#ff5050' if 'gamespy' in match.lower() else '#d4b820'
            string_rows += f'<tr><td style="color:{color};font-size:11px">{match}</td><td style="color:var(--text-dim);font-size:11px">{stype}</td><td style="color:var(--text-faint);font-size:11px">{func}</td></tr>'

    port_rows = ''
    for port, funcs in sorted(port_summary.items()):
        desc = GAMESPY_PORTS.get(port, 'Unknown')
        dead = '💀 DEAD' if port in GAMESPY_PORTS else ''
        port_rows += f'<tr><td style="color:var(--red);font-weight:700">{port}</td><td style="color:var(--text-dim)">{desc}</td><td style="color:var(--red);font-size:11px">{dead}</td><td style="color:var(--text-faint);font-size:11px">{", ".join(sorted(funcs)[:3])}</td></tr>'

    target_rows = ''
    for name, info in sorted(all_targets.items(), key=lambda x: len(x[1]['hits']), reverse=True):
        hits_html = ' '.join(f'<span class="hit">{h}</span>' for h in info['hits'][:6])
        vers_html = ' '.join(f'<span class="ver">{v[:8]}</span>' for v in info['versions'])
        target_rows += f'''<tr>
            <td class="fn">{name}</td>
            <td style="color:var(--gold-dim);font-size:11px">{info["address"]}</td>
            <td>{hits_html}</td>
            <td>{vers_html}</td>
        </tr>'''

    # Export patch targets JSON
    patch_json = json.dumps(list(all_targets.values()), indent=2)
    with open('ds2_network_patch_targets.json', 'w') as f:
        json.dump(list(all_targets.values()), f, indent=2)

    has_gamespy = bool(gs_summary)
    has_winhttp = 'winhttp' in dll_summary
    severity = 'CRITICAL' if has_gamespy else ('HIGH' if has_winhttp else 'MEDIUM')
    sev_color = '#e04040' if severity == 'CRITICAL' else '#e08020'

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>DS2 Network Dependency Report</title>
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
.main{{padding:22px 28px;max-width:1400px}}
h2{{font-family:'Cinzel',serif;color:var(--gold-dim);font-size:12px;letter-spacing:2px;
    margin:20px 0 10px;border-bottom:1px solid var(--border);padding-bottom:5px}}
.severity{{background:var(--bg2);border:2px solid {sev_color};border-radius:5px;
           padding:14px 20px;margin-bottom:18px;font-size:13px;line-height:1.8}}
.severity .big{{color:{sev_color};font-size:20px;font-weight:700;font-family:'Cinzel',serif}}
.note{{background:var(--bg2);border-left:3px solid var(--gold);padding:10px 14px;
       margin:8px 0 14px;color:var(--text-dim);font-size:12px;line-height:1.7}}
.revival{{background:#081408;border:1px solid #183018;border-radius:5px;
          padding:14px 20px;margin-bottom:16px;font-size:12px;line-height:2}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}}
th{{background:var(--bg3);color:var(--gold-dim);padding:7px 10px;text-align:left;
    border-bottom:2px solid var(--border);font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px}}
td{{padding:5px 10px;border-bottom:1px solid var(--bg3);vertical-align:middle}}
tr:hover td{{background:var(--bg2)}}
.fn{{color:#e8d5a0;font-weight:700;font-size:11px;word-break:break-all}}
.cat{{display:inline-block;font-size:10px;padding:1px 6px;border-radius:2px;margin:1px;white-space:nowrap}}
.cat-gs{{background:#200808;color:#ff6060;border:1px solid #500808}}
.hit{{display:inline-block;font-size:10px;padding:1px 5px;border-radius:2px;margin:1px;
      background:#0c0a08;color:var(--text-dim);border:1px solid var(--border2);white-space:nowrap}}
.ver{{display:inline-block;font-size:10px;padding:1px 5px;border-radius:2px;margin:1px;
      background:#0c1008;color:#60a040;border:1px solid #182010;white-space:nowrap}}
.json-box{{background:var(--bg2);border:1px solid var(--border);border-radius:4px;
           padding:14px;font-size:11px;color:var(--text-dim);overflow:auto;
           max-height:250px;white-space:pre;margin-top:8px}}
.copy-btn{{background:#2a1f0a;border:1px solid var(--gold-dim);color:var(--gold);
           padding:6px 14px;border-radius:3px;cursor:pointer;font-family:'Cinzel',serif;
           font-size:10px;letter-spacing:1px;margin-bottom:8px;display:inline-block}}
</style></head><body>
<div class="hdr">
  <h1>⚔ DS2 NETWORK DEPENDENCY REPORT</h1>
  <div class="sub">GameSpy Revival Analysis — {datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;|&nbsp;
  Versions: {", ".join(all_results.keys())}</div>
</div>
<div class="main">

<h2>SEVERITY ASSESSMENT</h2>
<div class="severity">
  <div class="big">{severity}</div>
  {"GameSpy SDK references found — multiplayer requires server revival or protocol reimplementation" if has_gamespy else ""}
  {"WinHTTP/WinINet found — likely used for HTTP-based server communication" if has_winhttp else ""}
  <br><span style="color:var(--text-dim);font-size:11px">
  {len(all_targets)} functions identified as patch targets for multiplayer revival
  </span>
</div>

<h2>MULTIPLAYER REVIVAL OPTIONS</h2>
<div class="revival">
  <span style="color:var(--green)">Option 1 — OpenSpy (easiest)</span><br>
  &nbsp;&nbsp;Redirect GameSpy DNS to OpenSpy servers via hosts file or stub DLL<br>
  &nbsp;&nbsp;Works if DS2 uses standard GameSpy SDK without custom modifications<br>
  &nbsp;&nbsp;→ na.openspy.net replaces master.gamespy.com<br><br>
  <span style="color:var(--yellow)">Option 2 — Stub DLL (medium)</span><br>
  &nbsp;&nbsp;Replace GameSpy DLLs with custom implementations pointing to community server<br>
  &nbsp;&nbsp;Intercept WinHTTP calls and redirect to new server address<br>
  &nbsp;&nbsp;No EXE modification needed — drop-in replacement DLLs<br><br>
  <span style="color:var(--orange)">Option 3 — EXE patch (hard)</span><br>
  &nbsp;&nbsp;Patch hardcoded server addresses directly in the binary<br>
  &nbsp;&nbsp;Modify the {len(all_targets)} identified patch target functions<br>
  &nbsp;&nbsp;Most reliable long-term but requires binary editing<br>
</div>

<h2>GAMESPY SDK COMPONENTS FOUND</h2>
{f'<div class="note">No GameSpy SDK references detected in scanned functions. GameSpy may be in a separate DLL rather than statically linked.</div>' if not gs_summary else ''}
<table>
  <tr><th>COMPONENT</th><th>FUNCTIONS</th><th>SAMPLE FUNCTIONS</th></tr>
  {gs_rows or '<tr><td colspan="3" style="color:var(--text-faint)">None detected</td></tr>'}
</table>

<h2>NETWORK DLL USAGE</h2>
<table>
  <tr><th>DLL / API</th><th>FUNCTIONS</th><th>SAMPLE FUNCTIONS</th></tr>
  {dll_rows or '<tr><td colspan="3" style="color:var(--text-faint)">None detected</td></tr>'}
</table>

<h2>HARDCODED SERVER STRINGS</h2>
<div class="note">These are the addresses/URLs that need to be patched or redirected for multiplayer revival.</div>
<table>
  <tr><th>STRING</th><th>TYPE</th><th>FOUND IN</th></tr>
  {string_rows or '<tr><td colspan="3" style="color:var(--text-faint)">No hardcoded server strings detected — addresses may be loaded from config or registry</td></tr>'}
</table>

<h2>GAMESPY PORT REFERENCES</h2>
<table>
  <tr><th>PORT</th><th>SERVICE</th><th>STATUS</th><th>FUNCTIONS</th></tr>
  {port_rows or '<tr><td colspan="4" style="color:var(--text-faint)">No GameSpy port references found in code</td></tr>'}
</table>

<h2>PATCH TARGETS — {len(all_targets)} FUNCTIONS</h2>
<div class="note">Functions that reference server addresses, GameSpy APIs, or network ports.
These are the functions that need modification for multiplayer revival.</div>
<table>
  <tr><th>FUNCTION</th><th>ADDRESS</th><th>REFERENCES</th><th>VERSIONS</th></tr>
  {target_rows or '<tr><td colspan="4" style="color:var(--text-faint)">No patch targets identified</td></tr>'}
</table>

<h2>PATCH TARGETS JSON</h2>
<div class="copy-btn" onclick="copyJson()">COPY TO CLIPBOARD</div>
<div class="json-box" id="jb">{patch_json[:3000]}{"..." if len(patch_json) > 3000 else ""}</div>

</div>
<script>
function copyJson(){{
  navigator.clipboard.writeText({json.dumps(patch_json)});
  document.querySelector('.copy-btn').textContent='COPIED!';
  setTimeout(()=>document.querySelector('.copy-btn').textContent='COPY TO CLIPBOARD',2000);
}}
</script>
</body></html>'''

    with open(output, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\n  [html] {output}")
    print(f"  [json] ds2_network_patch_targets.json")


def main():
    ap = argparse.ArgumentParser(description='DS2 Network & GameSpy Dependency Scanner')
    ap.add_argument('--dir',   default=None)
    ap.add_argument('--files', nargs='+')
    args = ap.parse_args()

    files = []
    if args.files:
        files = args.files
    elif args.dir:
        files = [str(f) for f in sorted(Path(args.dir).glob('*.c'))]

    if not files:
        print("No files. Use --dir or --files")
        return

    print(f"\n{'='*58}")
    print(f"  DS2 NETWORK SCANNER")
    print(f"{'='*58}\n")

    all_results = {}
    for f in files:
        if not os.path.exists(f):
            print(f"  [skip] {f}")
            continue
        label = Path(f).stem
        index = load_index(f)
        if not index:
            print(f"  [skip] No index for {label} — run ds2_differ.py first")
            continue
        print(f"\n[{label}]")
        all_results[label] = scan_file(f, index)

    if not all_results:
        print("No files could be scanned.")
        return

    print(f"\n[report] Generating...")
    make_report(all_results)

    # Summary
    total_targets = set()
    for r in all_results.values():
        for pt in r['patch_targets']:
            total_targets.add(pt['function'])

    print(f"\n{'='*58}")
    print(f"  COMPLETE")
    print(f"  Versions scanned : {len(all_results)}")
    print(f"  Patch targets    : {len(total_targets)}")
    print(f"\n  Next steps:")
    print(f"  1. Check report for hardcoded GameSpy domains")
    print(f"  2. If WinHTTP found — stub DLL approach likely easiest")
    print(f"  3. If GameSpy SDK statically linked — OpenSpy redirect first")
    print(f"{'='*58}\n")


if __name__ == '__main__':
    main()
