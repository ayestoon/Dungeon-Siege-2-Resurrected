#!/usr/bin/env python3
"""
DS2 Ghidra C Export Differ
Handles Ghidra C/C++ decompiler export format.
Usage:
    python ds2_differ.py file_a.c file_b.c
    python ds2_differ.py file_a.c file_b.c --label-a "v2.2" --label-b "v2.3"
    python ds2_differ.py file_a.c file_b.c --top 200
    python ds2_differ.py file_a.c file_b.c --no-cache
"""
import sys, os, re, json, time, argparse, difflib
from datetime import datetime
from pathlib import Path

FUNC_SIG_RE = re.compile(
    r'^(?:undefined\d*|void|int|uint|bool|char|uchar|short|ushort|long|ulong|float|double'
    r'|BOOL|DWORD|WORD|BYTE|HANDLE|LPVOID|HRESULT|LRESULT|HWND|HMODULE|FARPROC'
    r'|__cdecl|__stdcall|__fastcall|\w+\s*\*)\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*\('
)

CATS = {
    'memory':    re.compile(r'\b(VirtualAlloc|VirtualFree|HeapAlloc|HeapFree|malloc|free|GlobalAlloc)\b'),
    'hvci':      re.compile(r'\b(VirtualProtect|NtProtect|PAGE_EXECUTE|MEM_COMMIT|PAGE_EXECUTE_READWRITE)\b'),
    'directx':   re.compile(r'\b(IDirect3D|Direct3DCreate|D3D|CreateDevice|d3d8|d3d9)\b', re.I),
    'audio':     re.compile(r'\b(AIL_|miles|mss32|dsound|DirectSound|IDirectSound|waveOut)\b', re.I),
    'tank':      re.compile(r'\b(tank|TankFile|\.sno|siegelet|SiegeTank)\b', re.I),
    'node':      re.compile(r'\b(SiegeNode|NodeGraph|sno_|node_|NodeRef)\b', re.I),
    'timing':    re.compile(r'\b(QueryPerformanceCounter|timeGetTime|GetTickCount|Sleep|frametime)\b', re.I),
    'threading': re.compile(r'\b(CreateThread|WaitForSingle|EnterCriticalSection|InitializeCriticalSection)\b'),
    'fileio':    re.compile(r'\b(CreateFile|ReadFile|WriteFile|fopen|fread|fwrite)\b'),
    'bw':        re.compile(r'\b(broken_world|siegelet_load|bw_|expansion)\b', re.I),
}

CAT_DESC = {
    'memory':'VirtualAlloc/HeapAlloc — HVCI conflict risk',
    'hvci':'Memory protection flags — direct HVCI trigger',
    'directx':'DirectX 8/9 — driver model issues on modern Windows',
    'audio':'Miles Sound System / DirectSound — frame stall source',
    'tank':'Tank file / SNO loading — asset pipeline',
    'node':'Node graph logic — SNO node rebuild',
    'timing':'Frame timing — may be CPU-speed dependent',
    'threading':'Thread/mutex management — contention risk',
    'fileio':'File I/O — disk access patterns',
    'bw':'Broken World expansion — transition loading',
}

def build_index(filepath, cache_path=None):
    if cache_path and os.path.exists(cache_path):
        if os.path.getmtime(cache_path) > os.path.getmtime(filepath):
            print(f"  [cache] {cache_path}")
            with open(cache_path) as f: return json.load(f)
    sz = os.path.getsize(filepath)
    print(f"  [scan] {filepath}  ({sz/1024/1024:.1f} MB)")
    index = {}
    cur_func = cur_start = None
    brace_depth = 0
    in_body = False
    byte_off = line_n = 0
    t0 = time.time()
    with open(filepath, 'rb') as f:
        for raw in f:
            line_n += 1
            line = raw.decode('utf-8', errors='replace')
            if line_n % 300_000 == 0:
                print(f"         {byte_off/sz*100:.1f}%  {len(index):,} funcs  {time.time()-t0:.0f}s", end='\r')
            s = line.strip()
            if not in_body:
                m = FUNC_SIG_RE.match(s)
                if m:
                    cur_func  = m.group(1)
                    cur_start = byte_off
                    brace_depth = 0
                if cur_func:
                    brace_depth += line.count('{') - line.count('}')
                    if line.count('{') > 0: in_body = True
            else:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    size = byte_off + len(raw) - cur_start
                    if cur_func and cur_func not in index:
                        index[cur_func] = {'offset': cur_start, 'size': size}
                    cur_func = None; in_body = False; brace_depth = 0
            byte_off += len(raw)
    print(f"\n  [done] {len(index):,} functions in {time.time()-t0:.1f}s")
    if cache_path:
        with open(cache_path,'w') as f: json.dump(index, f)
        print(f"  [save] {cache_path}")
    return index

def read_func(path, offset, size, cap=65536):
    with open(path,'rb') as f:
        f.seek(offset)
        return f.read(min(size,cap)).decode('utf-8',errors='replace')

def norm(t):
    t = re.sub(r'0x[0-9a-fA-F]+','HEX',t)
    t = re.sub(r'\bFUN_[0-9a-fA-F]+\b','FUN',t)
    t = re.sub(r'\bDAT_[0-9a-fA-F]+\b','DAT',t)
    t = re.sub(r'\bLAB_[0-9a-fA-F]+\b','LAB',t)
    t = re.sub(r'\b\d+\b','NUM',t)
    t = re.sub(r'//.*$','',t,flags=re.MULTILINE)
    return re.sub(r'\s+',' ',t).strip().lower()

def sim(a,b):
    na,nb = norm(a),norm(b)
    if not na and not nb: return 1.0
    if not na or not nb:  return 0.0
    fn = difflib.SequenceMatcher(None,na,nb)
    return fn.ratio() if len(na)+len(nb)<20000 else fn.quick_ratio()

def detect(t): return [k for k,p in CATS.items() if p.search(t)]

def pri(score,status,cats):
    if status=='removed': return 'HIGH'
    if status=='added' and cats: return 'HIGH'
    if status=='added': return 'MEDIUM'
    if score<0.5 and cats: return 'CRITICAL'
    if score<0.5: return 'HIGH'
    if score<0.8: return 'MEDIUM'
    if score<0.99: return 'LOW'
    return 'NONE'

def diff_indexes(fa,ia,fb,ib,top_n=None):
    funcs = sorted(set(ia)|set(ib))
    print(f"\n  [diff] {len(funcs):,} functions...")
    results=[]; done=0; t0=time.time()
    for name in funcs:
        in_a,in_b = name in ia, name in ib
        if in_a and in_b:
            ta=read_func(fa,ia[name]['offset'],ia[name]['size'])
            tb=read_func(fb,ib[name]['offset'],ib[name]['size'])
            sc=sim(ta,tb); cats=list(set(detect(ta))|set(detect(tb)))
            status='identical' if sc>=0.99 else 'changed'
            sa,sb=ia[name]['size'],ib[name]['size']
        elif in_a:
            ta=read_func(fa,ia[name]['offset'],ia[name]['size'])
            sc=0.0;cats=detect(ta);status='removed';sa,sb=ia[name]['size'],0
        else:
            tb=read_func(fb,ib[name]['offset'],ib[name]['size'])
            sc=0.0;cats=detect(tb);status='added';sa,sb=0,ib[name]['size']
        results.append({'name':name,'score':sc,'status':status,'categories':cats,
                        'priority':pri(sc,status,cats),'size_a':sa,'size_b':sb})
        done+=1
        if done%500==0: print(f"         {done:,}/{len(funcs):,}  ({time.time()-t0:.0f}s)",end='\r')
    print(f"\n  [done] {len(results):,} compared in {time.time()-t0:.1f}s")
    results.sort(key=lambda r:({'changed':0,'removed':1,'added':2,'identical':3}[r['status']],r['score']))
    if top_n:
        ni=[r for r in results if r['status']!='identical']
        id_=[r for r in results if r['status']=='identical'][:max(0,top_n-len(ni))]
        results=ni+id_
    return results

SB={'identical':'<span class="badge b-id">IDENTICAL</span>',
    'changed':'<span class="badge b-ch">CHANGED</span>',
    'added':'<span class="badge b-ad">ADDED</span>',
    'removed':'<span class="badge b-rm">REMOVED</span>'}
PB={'CRITICAL':'<span class="badge b-cr">⚠ CRITICAL</span>',
    'HIGH':'<span class="badge b-hi">HIGH</span>',
    'MEDIUM':'<span class="badge b-md">MEDIUM</span>',
    'LOW':'<span class="badge b-lo">LOW</span>','NONE':''}

def sc_col(s,st):
    if st=='added': return '#4ab4d8'
    if st=='removed': return '#e04040'
    if s>=0.99: return '#50b860'
    if s>=0.8:  return '#d4b820'
    if s>=0.5:  return '#e08020'
    return '#e04040'

def make_report(results,la,lb,fa,fb,out):
    total=len(results)
    ident=sum(1 for r in results if r['status']=='identical')
    chg=sum(1 for r in results if r['status']=='changed')
    add=sum(1 for r in results if r['status']=='added')
    rem=sum(1 for r in results if r['status']=='removed')
    crit=sum(1 for r in results if r['priority']=='CRITICAL')
    high=sum(1 for r in results if r['priority']=='HIGH')
    cat_counts={}
    for r in results:
        if r['status']!='identical':
            for c in r['categories']: cat_counts[c]=cat_counts.get(c,0)+1
    cat_rows=''.join(
        f'<tr><td><span class="cat cat-{c}">{c}</span></td>'
        f'<td style="color:var(--orange);font-weight:700">{n}</td>'
        f'<td style="color:var(--text-dim);font-size:11px">{CAT_DESC.get(c,"")}</td></tr>'
        for c,n in sorted(cat_counts.items(),key=lambda x:-x[1])
    ) or '<tr><td colspan="3" style="color:var(--text-faint)">No DS2-specific patterns found in changed functions</td></tr>'
    rows=[]
    for r in results:
        sp=int(r['score']*100); col=sc_col(r['score'],r['status'])
        cats=''.join(f'<span class="cat cat-{c}">{c}</span>' for c in sorted(r['categories']))
        if r['size_a'] and r['size_b']: sz=f"{r['size_a']//1024}K→{r['size_b']//1024}K"
        elif r['size_b']: sz=f"+{r['size_b']//1024}K"
        else: sz=f"-{r['size_a']//1024}K"
        rows.append(f'<tr class="fr" data-status="{r["status"]}" data-pri="{r["priority"]}" '
            f'data-score="{r["score"]:.4f}" data-name="{r["name"].lower()}">'
            f'<td class="fn">{r["name"]}</td><td>{SB[r["status"]]}</td>'
            f'<td>{PB.get(r["priority"],"")}</td>'
            f'<td><div class="bw"><div class="bb" style="width:{sp}%;background:{col}"></div></div>'
            f'<span style="color:{col};font-weight:700">{sp}%</span></td>'
            f'<td class="cats">{cats}</td><td class="sz">{sz}</td></tr>')
    html=f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>DS2 Diff — {la} vs {lb}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&family=Share+Tech+Mono&display=swap');
:root{{--bg:#070604;--bg1:#0c0a06;--bg2:#111008;--bg3:#181508;--border:#2a2010;--border2:#3a3018;
--gold:#c8a84b;--gold-dim:#6a5a28;--text:#c8b87a;--text-dim:#7a6840;--text-faint:#3a3018;
--red:#e04040;--orange:#e08020;--yellow:#d4b820;--blue:#4ab4d8;--green:#50b860;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;font-size:13px}}
.hdr{{background:linear-gradient(180deg,#1a1200,#0c0a06);border-bottom:1px solid var(--border);padding:20px 28px}}
.hdr h1{{font-family:'Cinzel',serif;color:var(--gold);font-size:24px;letter-spacing:3px}}
.sub{{color:var(--text-dim);font-size:13px;margin-top:5px}}
.meta{{color:var(--gold-dim);font-size:11px;margin-top:3px}}
.main{{padding:22px 28px;max-width:1500px}}
h2{{font-family:'Cinzel',serif;color:var(--gold-dim);font-size:13px;letter-spacing:2px;margin:20px 0 10px;border-bottom:1px solid var(--border);padding-bottom:5px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:10px 18px;text-align:center;min-width:90px}}
.sv{{font-size:22px;font-weight:700}}.sl{{color:var(--text-dim);font-size:10px;font-family:'Cinzel',serif;letter-spacing:1px;margin-top:2px}}
.ctab{{border-collapse:collapse;width:100%;margin-bottom:16px;font-size:12px}}
.ctab td{{padding:6px 12px;border-bottom:1px solid var(--border)}}
.ctab th{{background:var(--bg3);color:var(--gold-dim);padding:7px 12px;text-align:left;border-bottom:2px solid var(--border);font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px}}
.ctab tr:hover td{{background:var(--bg2)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}}
.fb{{background:var(--bg2);border:1px solid var(--border2);color:var(--text-dim);padding:5px 13px;border-radius:3px;cursor:pointer;font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px;transition:all .15s}}
.fb.on{{background:#2a1f0a;border-color:var(--gold);color:var(--gold)}}
.fb.crit{{color:var(--red)}}
.srch{{background:var(--bg2);border:1px solid var(--border2);color:var(--text);padding:6px 12px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:12px;width:240px;outline:none}}
.srch:focus{{border-color:var(--gold-dim)}}
.cnt{{color:var(--text-faint);font-size:11px;margin-left:auto}}
table.ft{{width:100%;border-collapse:collapse;font-size:12px}}
table.ft th{{background:var(--bg3);color:var(--gold-dim);padding:8px 10px;text-align:left;border-bottom:2px solid var(--border);font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px;cursor:pointer;user-select:none;white-space:nowrap}}
table.ft th:hover{{color:var(--gold)}}
table.ft td{{padding:6px 10px;border-bottom:1px solid var(--bg3);vertical-align:middle}}
.fr:hover td{{background:var(--bg2)}}.fr.hide{{display:none}}
.fn{{color:#e8d5a0;font-weight:700;word-break:break-all;max-width:400px}}
.sz{{color:var(--text-faint);font-size:11px;white-space:nowrap}}
.cats{{max-width:280px}}
.bw{{width:70px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:6px}}
.bb{{height:100%;border-radius:3px}}
.badge{{display:inline-block;font-size:10px;font-weight:700;letter-spacing:1px;padding:2px 7px;border-radius:2px;white-space:nowrap}}
.b-id{{background:#081408;color:var(--green);border:1px solid #103010}}
.b-ch{{background:#181008;color:var(--orange);border:1px solid #402010}}
.b-ad{{background:#081018;color:var(--blue);border:1px solid #102030}}
.b-rm{{background:#200808;color:var(--red);border:1px solid #400808}}
.b-cr{{background:#200808;color:var(--red);border:1px solid #500a0a}}
.b-hi{{background:#180c04;color:var(--orange);border:1px solid #402010}}
.b-md{{background:#141208;color:var(--yellow);border:1px solid #382808}}
.b-lo{{background:#0a0c0a;color:#607060;border:1px solid #1a2010}}
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
.cat-bw{{background:#1a1008;color:#d09040;border:1px solid #402810}}
.note{{background:var(--bg2);border-left:3px solid var(--gold);padding:10px 14px;margin:8px 0 14px;color:var(--text-dim);font-size:12px;line-height:1.7}}
</style></head><body>
<div class="hdr">
  <h1>⚔ DS2 EXECUTABLE DIFF REPORT</h1>
  <div class="sub">{la}  →  {lb}</div>
  <div class="meta">Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;|&nbsp; {os.path.basename(fa)} vs {os.path.basename(fb)}</div>
</div>
<div class="main">
<h2>SUMMARY</h2>
<div class="stats">
  <div class="stat"><div class="sv" style="color:var(--text)">{total:,}</div><div class="sl">TOTAL</div></div>
  <div class="stat"><div class="sv" style="color:var(--red)">{crit}</div><div class="sl">CRITICAL</div></div>
  <div class="stat"><div class="sv" style="color:var(--orange)">{high}</div><div class="sl">HIGH</div></div>
  <div class="stat"><div class="sv" style="color:var(--orange)">{chg:,}</div><div class="sl">CHANGED</div></div>
  <div class="stat"><div class="sv" style="color:var(--blue)">{add:,}</div><div class="sl">ADDED</div></div>
  <div class="stat"><div class="sv" style="color:var(--red)">{rem:,}</div><div class="sl">REMOVED</div></div>
  <div class="stat"><div class="sv" style="color:var(--green)">{ident:,}</div><div class="sl">IDENTICAL</div></div>
</div>
<h2>DS2-RELEVANT CATEGORIES IN CHANGED FUNCTIONS</h2>
<div class="note">Functions that changed between versions AND contain DS2-specific patterns. Higher count = more modified functions in that system. These are your primary investigation targets.</div>
<table class="ctab"><tr><th>Category</th><th>Modified Functions</th><th>Why It Matters</th></tr>{cat_rows}</table>
<h2>FUNCTION DIFF TABLE</h2>
<div class="note">Similarity 0% = completely rewritten. 100% = identical logic. Click column headers to sort. Use filters to focus on what matters.</div>
<div class="filters">
  <button class="fb on" onclick="fs('all')">ALL</button>
  <button class="fb" onclick="fs('changed')">CHANGED</button>
  <button class="fb" onclick="fs('added')">ADDED</button>
  <button class="fb" onclick="fs('removed')">REMOVED</button>
  <button class="fb" onclick="fs('identical')">IDENTICAL</button>
  <button class="fb crit" onclick="fp()">⚠ CRITICAL ONLY</button>
  <input class="srch" type="text" placeholder="Search function name..." oninput="fq(this.value)">
  <span class="cnt" id="ci">{total:,} functions</span>
</div>
<table class="ft"><thead><tr>
  <th onclick="st(0)">FUNCTION NAME ▾</th>
  <th onclick="st(1)">STATUS ▾</th>
  <th onclick="st(2)">PRIORITY ▾</th>
  <th onclick="st(3)">SIMILARITY ▾</th>
  <th>CATEGORIES</th>
  <th>SIZE</th>
</tr></thead><tbody id="tb">
{''.join(rows)}
</tbody></table>
</div>
<script>
const T={total};let cS='all',cP=false,cQ='';
function upd(){{let v=0;document.querySelectorAll('.fr').forEach(r=>{{
const ok=(cS==='all'||r.dataset.status===cS)&&(!cP||r.dataset.pri==='CRITICAL')&&(!cQ||r.dataset.name.includes(cQ));
r.classList.toggle('hide',!ok);if(ok)v++;}});
document.getElementById('ci').textContent=v.toLocaleString()+' / '+T.toLocaleString()+' functions';}}
function fs(s){{cS=s;document.querySelectorAll('.fb').forEach(b=>b.classList.toggle('on',b.textContent===s.toUpperCase()||(s==='all'&&b.textContent==='ALL')));upd();}}
function fp(){{cP=!cP;document.querySelector('.fb.crit').classList.toggle('on',cP);upd();}}
function fq(v){{cQ=v.toLowerCase();upd();}}
function st(c){{const tb=document.getElementById('tb');const rows=[...tb.querySelectorAll('.fr')];
const asc=tb.dataset['s'+c]!=='1';tb.dataset['s'+c]=asc?'1':'';
rows.sort((a,b)=>{{if(c===3){{const d=parseFloat(a.dataset.score)-parseFloat(b.dataset.score);return asc?d:-d;}}
const av=a.cells[c]?.textContent.trim()||'';const bv=b.cells[c]?.textContent.trim()||'';return asc?av.localeCompare(bv):bv.localeCompare(av);}});
rows.forEach(r=>tb.appendChild(r));}}
</script></body></html>'''
    with open(out,'w',encoding='utf-8') as f: f.write(html)
    print(f"\n  [html] {out}  ({os.path.getsize(out)//1024} KB)")

def main():
    ap=argparse.ArgumentParser(description='DS2 Ghidra C Export Differ')
    ap.add_argument('file_a'); ap.add_argument('file_b')
    ap.add_argument('--label-a',default=None); ap.add_argument('--label-b',default=None)
    ap.add_argument('--output',default='ds2_diff_report.html')
    ap.add_argument('--top',type=int,default=None)
    ap.add_argument('--no-cache',action='store_true')
    args=ap.parse_args()
    for f in [args.file_a,args.file_b]:
        if not os.path.exists(f): print(f"ERROR: {f}"); sys.exit(1)
    la=args.label_a or Path(args.file_a).stem
    lb=args.label_b or Path(args.file_b).stem
    print(f"\n{'='*56}\n  DS2 EXE DIFFER  |  {la}  →  {lb}\n{'='*56}\n")
    ca=None if args.no_cache else str(Path(args.file_a).with_suffix('.diff_index.json'))
    cb=None if args.no_cache else str(Path(args.file_b).with_suffix('.diff_index.json'))
    print("[1/3] Indexing baseline...")
    ia=build_index(args.file_a,ca)
    print(f"\n[2/3] Indexing comparison...")
    ib=build_index(args.file_b,cb)
    print(f"\n[3/3] Comparing...")
    results=diff_indexes(args.file_a,ia,args.file_b,ib,top_n=args.top)
    print(f"\n[4/4] Generating report...")
    make_report(results,la,lb,args.file_a,args.file_b,args.output)
    crits=[r for r in results if r['priority']=='CRITICAL']
    print(f"\n{'='*56}\n  COMPLETE  |  {len(results):,} functions  |  {len(crits)} critical")
    if crits:
        print(f"\n  Critical functions:")
        for r in crits[:8]:
            print(f"    [{r['score']*100:3.0f}%]  {r['name']:<40}  {','.join(r['categories'])}")
    print(f"\n  Report: {args.output}\n{'='*56}\n")

if __name__=='__main__': main()
