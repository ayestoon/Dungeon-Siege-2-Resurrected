#!/usr/bin/env python3
"""
DS2 AI Function Analyzer
=========================
Uses the Anthropic API to analyze unknown DS2 functions and identify
what they do — targeting the critical and high priority functions
from the diff reports first.

Features:
  - Resumable — tracks what's already been analyzed, never double-bills
  - Cost preview — shows estimated cost before spending anything
  - Prioritized — processes CRITICAL first, then HIGH, then others
  - Context-aware — sends caller/callee context for better analysis
  - Batch mode — processes overnight without supervision
  - Results feed back into ds2_survey.py priority queue

Usage:
    # Preview cost only — no API calls
    python ds2_analyze.py --preview --queue ds2_priority_queue.json --dir "C:\\DS2\\eXPORT"

    # Analyze top 100 critical/high functions
    python ds2_analyze.py --limit 100 --queue ds2_priority_queue.json --dir "C:\\DS2\\eXPORT"

    # Full batch run overnight
    python ds2_analyze.py --limit 500 --queue ds2_priority_queue.json --dir "C:\\DS2\\eXPORT" --batch

    # Analyze specific functions from diff report
    python ds2_analyze.py --diff "ds2_diff_report.html" --dir "C:\\DS2\\eXPORT" --limit 50

    # View results so far
    python ds2_analyze.py --results

Requirements:
    pip install anthropic
    ANTHROPIC_API_KEY environment variable set

Output:
    ds2_analysis_results.json    — all results, resumable checkpoint
    ds2_analysis_report.html     — visual report of findings
    ds2_ghidra_comments.py       — Ghidra script to apply results as comments
"""

import os
import re
import sys
import json
import time
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# ── Config ────────────────────────────────────────────────────────────────────

MODEL         = 'claude-sonnet-4-20250514'  # Anthropic fallback
MAX_TOKENS    = 400       # short focused answers only
BODY_CAP      = 3000      # max chars of function body to send
CONTEXT_CAP   = 800       # max chars of caller context
RESULTS_FILE  = 'ds2_analysis_results.json'
REPORT_FILE   = 'ds2_analysis_report.html'
GHIDRA_FILE   = 'ds2_ghidra_comments.py'

# Ollama config
OLLAMA_HOST   = 'http://localhost:11434'
OLLAMA_MODEL  = 'mistral'   # good balance of speed/quality for code analysis
                             # alternatives: codellama, llama3, deepseek-coder

# Cost estimate (Anthropic Sonnet pricing — Ollama is FREE)
INPUT_COST_PER_M  = 3.00
OUTPUT_COST_PER_M = 15.00
AVG_INPUT_TOKENS  = 600
AVG_OUTPUT_TOKENS = 150

# DS2-specific context for the AI
DS2_SYSTEM_PROMPT = """You are a reverse engineering assistant analyzing Dungeon Siege 2 (DS2) game executable functions.

DS2 is a 2005 action RPG by Gas Powered Games, built on the Siege Engine.
Key subsystems to recognize:
- Tank file system (.dsres/.dsmap archives, proprietary format)
- Siege Node (SNO) 3D scene graph system
- Miles Sound System (MSS32) audio
- GameSpy SDK multiplayer (GP protocol, server browser)
- SafeDisc v3 DRM (being removed in community patch)
- DirectX 9 rendering pipeline
- gpbstring<char> custom string class
- UIFrontend class hierarchy for menus
- Siegelet system for expansion content loading

Address ranges and their likely subsystems:
- 0x004xxxxx: startup, initialization, core engine low
- 0x004fxxxx: CD key / authentication / GameSpy integration (CRITICAL)
- 0x005xxxxx: core engine mid
- 0x006xxxxx: game logic A
- 0x007xxxxx: game logic B  
- 0x008xxxxx: game logic C / audio (0x008xxxxx had SafeDisc hooks)
- 0x009xxxxx: game logic D / network
- 0x00axxxxx: expansion (Broken World) content
- 0x00bxxxxx: SafeDisc unpacker region (being removed)

When analyzing a function:
1. Identify what it does in 1-2 sentences
2. Name the likely subsystem (audio/network/cdkey/rendering/ui/tank/sno/input/memory)
3. Flag if it appears to be SafeDisc-related
4. Flag if it appears to be GameSpy/multiplayer-related
5. Flag if it touches memory allocation (VirtualAlloc/HeapAlloc/malloc)
6. Suggest a meaningful name like: AudioSystem_InitDevice or CDKey_ValidateSerial

Keep answers concise — max 3 sentences. Format as JSON."""

ANALYSIS_PROMPT_TEMPLATE = """Analyze this DS2 function:

Address: {addr}
Diff status: {diff_status} ({diff_pct}% similar to Reloaded build)
Priority: {priority}

Function body (decompiled pseudocode):
```c
{body}
```

{context_section}

Respond ONLY with valid JSON, no markdown, no explanation outside JSON:
{{
  "name": "SubSystem_FunctionPurpose",
  "description": "What this function does in 1-2 sentences",
  "subsystem": "one of: audio/network/cdkey/rendering/ui/tank/sno/input/memory/safedisc/gamespy/core/unknown",
  "safedisc_related": true/false,
  "gamespy_related": true/false,
  "memory_related": true/false,
  "patch_candidate": true/false,
  "confidence": "high/medium/low",
  "notes": "any additional observations or null"
}}"""


# ── File reader ────────────────────────────────────────────────────────────────

def read_func_body(c_file, offset, size, cap=BODY_CAP):
    """Read function body from C export file."""
    try:
        with open(c_file, 'rb') as f:
            f.seek(offset)
            raw = f.read(min(size, cap))
        return raw.decode('utf-8', errors='replace')
    except Exception:
        return ''


def load_index(c_file):
    """Load diff_index.json cache for a C export."""
    cache = str(Path(c_file).with_suffix('.diff_index.json'))
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    return {}


def find_c_exports(export_dir):
    """Find all C export files with their indexes."""
    exports = {}
    for c_file in Path(export_dir).glob('*.c'):
        idx = load_index(str(c_file))
        if idx:
            exports[c_file.stem] = {'file': str(c_file), 'index': idx}
    return exports


# ── Queue loaders ─────────────────────────────────────────────────────────────

def load_queue_from_json(queue_file):
    """Load priority queue from ds2_survey.py output."""
    with open(queue_file) as f:
        items = json.load(f)
    return [{
        'name': item['name'],
        'address': item.get('address', '?'),
        'priority': item.get('diff_priority', 'UNKNOWN'),
        'diff_score': item.get('diff_score', 1.0),
        'priority_score': item.get('priority_score', 0),
        'categories': item.get('categories', []),
        'range': item.get('range', 'unknown'),
    } for item in items]


def load_queue_from_diff(diff_html):
    """Load priority queue directly from a diff HTML report."""
    with open(diff_html, encoding='utf-8', errors='replace') as f:
        content = f.read()
    rows = re.findall(
        r'data-status="(\w+)"\s+data-pri="(\w+)"\s+data-score="([\d.]+)"\s+data-name="([^"]+)"',
        content
    )
    items = []
    for status, priority, score, name in rows:
        if status not in ('changed',):
            continue
        if not name.startswith('fun_'):
            continue
        addr = '0x' + name[4:] if name.startswith('fun_') else '?'
        items.append({
            'name': name,
            'address': addr,
            'priority': priority,
            'diff_score': float(score),
            'priority_score': int((1.0 - float(score)) * 1000),
            'categories': [],
            'range': 'unknown',
            'diff_status': status,
        })
    # Sort by priority then score
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    items.sort(key=lambda x: (priority_order.get(x['priority'], 4), x['diff_score']))
    return items


# ── Results manager ───────────────────────────────────────────────────────────

class ResultsManager:
    def __init__(self, results_file=RESULTS_FILE):
        self.results_file = results_file
        self.results = {}
        self.load()

    def load(self):
        if os.path.exists(self.results_file):
            with open(self.results_file) as f:
                data = json.load(f)
            self.results = {r['name']: r for r in data.get('results', [])}
            print(f"  Loaded {len(self.results)} existing results from {self.results_file}")

    def save(self):
        data = {
            'generated': datetime.now().isoformat(),
            'count': len(self.results),
            'results': list(self.results.values())
        }
        with open(self.results_file, 'w') as f:
            json.dump(data, f, indent=2)

    def has(self, name):
        return name in self.results

    def add(self, name, address, analysis, raw_response, prompt_tokens, completion_tokens):
        self.results[name] = {
            'name': name,
            'address': address,
            'analyzed_at': datetime.now().isoformat(),
            'analysis': analysis,
            'raw_response': raw_response,
            'tokens': {
                'prompt': prompt_tokens,
                'completion': completion_tokens,
                'total': prompt_tokens + completion_tokens,
            },
            'cost_usd': (prompt_tokens * INPUT_COST_PER_M / 1_000_000) +
                        (completion_tokens * OUTPUT_COST_PER_M / 1_000_000),
        }

    def total_cost(self):
        return sum(r.get('cost_usd', 0) for r in self.results.values())

    def total_tokens(self):
        return sum(r.get('tokens', {}).get('total', 0) for r in self.results.values())


# ── Analyzer ──────────────────────────────────────────────────────────────────

# ── Ollama client ─────────────────────────────────────────────────────────────

def ollama_list_models():
    """List available Ollama models."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return [m['name'] for m in data.get('models', [])]
    except Exception:
        return []


def ollama_available():
    """Check if Ollama is running."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def ollama_chat(model, system_prompt, user_prompt, max_tokens=400):
    """Send a chat request to Ollama and return (text, prompt_tokens, completion_tokens)."""
    import json as _json

    payload = _json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt},
        ],
        'stream': False,
        'options': {
            'num_predict': max_tokens,
            'temperature': 0.1,  # low temp for consistent structured output
        }
    }).encode('utf-8')

    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat",
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = _json.loads(resp.read())
            text = data.get('message', {}).get('content', '')
            # Ollama doesn't always return token counts but sometimes does
            eval_count = data.get('eval_count', len(text.split()) * 2)
            prompt_eval = data.get('prompt_eval_count', len(user_prompt.split()) * 2)
            return text, prompt_eval, eval_count
    except urllib.error.URLError as e:
        raise Exception(f"Ollama connection failed: {e}")


def detect_backend(prefer_ollama=True):
    """Auto-detect available backend."""
    if prefer_ollama and ollama_available():
        models = ollama_list_models()
        # Pick best available model for code analysis
        preferred = ['deepseek-coder', 'codellama', 'mistral', 'llama3',
                     'llama2', 'phi', 'gemma', 'qwen']
        for pref in preferred:
            for m in models:
                if pref in m.lower():
                    return 'ollama', m
        # Use whatever is available
        if models:
            return 'ollama', models[0]

    if HAS_ANTHROPIC and os.environ.get('ANTHROPIC_API_KEY'):
        return 'anthropic', MODEL

    return None, None


class DS2Analyzer:
    def __init__(self, export_dir, results_manager, backend=None, model=None):
        self.exports = find_c_exports(export_dir)
        self.results = results_manager

        # Auto-detect backend
        if backend and model:
            self.backend = backend
            self.model = model
        else:
            self.backend, self.model = detect_backend()

        if self.backend == 'ollama':
            self.client = None
            print(f"  Backend: Ollama ({self.model}) — FREE, local")
        elif self.backend == 'anthropic':
            self.client = anthropic.Anthropic()
            print(f"  Backend: Anthropic API ({self.model})")
        else:
            self.client = None
            print(f"  WARNING: No backend available")
            print(f"    Option 1: Start Ollama — ollama serve")
            print(f"    Option 2: Set ANTHROPIC_API_KEY env var")

        print(f"  C exports loaded: {list(self.exports.keys())}")

    def find_function(self, func_name):
        """Find a function across all C exports."""
        # Try both cases — diff report uses fun_ lowercase, Ghidra dump uses FUN_ uppercase
        variants = [func_name, func_name.upper(), func_name.lower(),
                    'FUN_' + func_name[4:] if func_name.lower().startswith('fun_') else func_name,
                    'fun_' + func_name[4:] if func_name.upper().startswith('FUN_') else func_name]
        for label, data in self.exports.items():
            idx = data['index']
            for variant in variants:
                if variant in idx:
                    return data['file'], idx[variant], label
        return None, None, None

    def get_body(self, func_name):
        """Get decompiled function body."""
        c_file, info, label = self.find_function(func_name)
        if not c_file or not info:
            return '', label or 'unknown'
        body = read_func_body(c_file, info['offset'], info['size'])
        return body, label

    def get_context(self, func_name, body):
        """Build caller/callee context."""
        context_lines = []

        # Extract called functions from body
        called = re.findall(r'\b(fun_[0-9a-fA-F]+)\b', body)
        called = list(set(called))[:5]
        if called:
            context_lines.append(f"Calls: {', '.join(called)}")

        # Extract API calls
        api_calls = re.findall(r'\b([A-Z][a-zA-Z]+(?:Ex)?)\s*\(', body)
        api_calls = [a for a in set(api_calls) if len(a) > 4][:8]
        if api_calls:
            context_lines.append(f"Win32 APIs: {', '.join(api_calls)}")

        # Extract string literals
        strings = re.findall(r'"([^"]{4,40})"', body)[:5]
        if strings:
            context_lines.append(f"String literals: {strings}")

        return '\n'.join(context_lines)

    def build_prompt(self, item, body, context):
        """Build the analysis prompt for a function."""
        addr = item.get('address', '?')
        diff_pct = int(item.get('diff_score', 1.0) * 100)
        priority = item.get('priority', 'UNKNOWN')
        diff_status = item.get('diff_status', 'changed')

        context_section = f"Context:\n{context}" if context else ""

        # Truncate body if needed
        if len(body) > BODY_CAP:
            body = body[:BODY_CAP] + '\n// ... truncated ...'

        return ANALYSIS_PROMPT_TEMPLATE.format(
            addr=addr,
            diff_status=diff_status,
            diff_pct=diff_pct,
            priority=priority,
            body=body,
            context_section=context_section,
        )

    def analyze_function(self, item):
        """Send a function to the backend for analysis."""
        name = item['name']
        body, source = self.get_body(name)

        if not body:
            return None, 0, 0

        context = self.get_context(name, body)
        prompt = self.build_prompt(item, body, context)

        try:
            if self.backend == 'ollama':
                raw, prompt_tokens, completion_tokens = ollama_chat(
                    self.model,
                    DS2_SYSTEM_PROMPT,
                    prompt,
                    max_tokens=MAX_TOKENS
                )
            elif self.backend == 'anthropic' and self.client:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=MAX_TOKENS,
                    system=DS2_SYSTEM_PROMPT,
                    messages=[{'role': 'user', 'content': prompt}]
                )
                raw = response.content[0].text.strip()
                prompt_tokens = response.usage.input_tokens
                completion_tokens = response.usage.output_tokens
            else:
                return None, 0, 0

            # Parse JSON response
            clean = re.sub(r'^```json\s*', '', raw.strip())
            clean = re.sub(r'\s*```$', '', clean).strip()

            try:
                analysis = json.loads(clean)
            except json.JSONDecodeError:
                json_match = re.search(r'\{[^{}]+\}', clean, re.DOTALL)
                if json_match:
                    try:
                        analysis = json.loads(json_match.group())
                    except Exception:
                        analysis = {
                            'name': name, 'description': raw[:200],
                            'subsystem': 'unknown', 'confidence': 'low',
                            'safedisc_related': False, 'gamespy_related': False,
                            'memory_related': False, 'patch_candidate': False,
                            'error': 'json_parse_failed'
                        }
                else:
                    analysis = {
                        'name': name, 'description': raw[:200],
                        'subsystem': 'unknown', 'confidence': 'low',
                        'safedisc_related': False, 'gamespy_related': False,
                        'memory_related': False, 'patch_candidate': False,
                        'error': 'no_json_found'
                    }

            return analysis, prompt_tokens, completion_tokens

        except Exception as e:
            print(f"    Error: {e}")
            return None, 0, 0


# ── Cost preview ──────────────────────────────────────────────────────────────

def preview_cost(queue, limit, already_done):
    """Show cost estimate before spending anything."""
    pending = [i for i in queue if i['name'] not in already_done][:limit]

    by_priority = defaultdict(list)
    for item in pending:
        by_priority[item['priority']].append(item)

    est_input  = len(pending) * AVG_INPUT_TOKENS
    est_output = len(pending) * AVG_OUTPUT_TOKENS
    est_cost   = (est_input * INPUT_COST_PER_M / 1_000_000) + \
                 (est_output * OUTPUT_COST_PER_M / 1_000_000)

    print(f"\n{'='*55}")
    print(f"  COST PREVIEW")
    print(f"{'='*55}")
    print(f"  Queue size:        {len(queue):,} functions")
    print(f"  Already analyzed:  {len(already_done):,}")
    print(f"  To analyze now:    {len(pending):,}")
    print(f"")
    print(f"  By priority:")
    for pri in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        count = len(by_priority.get(pri, []))
        if count:
            cost = count * AVG_INPUT_TOKENS * INPUT_COST_PER_M / 1_000_000 + \
                   count * AVG_OUTPUT_TOKENS * OUTPUT_COST_PER_M / 1_000_000
            print(f"    {pri:10s}: {count:5,} functions  ~${cost:.2f}")
    print(f"")
    print(f"  Estimated cost:    ~${est_cost:.2f} USD")
    print(f"  Estimated tokens:  ~{est_input + est_output:,}")
    print(f"  Model:             {MODEL}")
    print(f"{'='*55}")

    return pending, est_cost


# ── HTML Report ────────────────────────────────────────────────────────────────

def make_report(results_manager):
    """Generate HTML report of analysis results."""
    results = list(results_manager.results.values())
    if not results:
        print("  No results to report yet.")
        return

    by_subsystem = defaultdict(list)
    by_priority_flag = {'safedisc': [], 'gamespy': [], 'memory': [], 'patch': []}

    for r in results:
        a = r.get('analysis', {})
        subsystem = a.get('subsystem', 'unknown')
        by_subsystem[subsystem].append(r)
        if a.get('safedisc_related'): by_priority_flag['safedisc'].append(r)
        if a.get('gamespy_related'):  by_priority_flag['gamespy'].append(r)
        if a.get('memory_related'):   by_priority_flag['memory'].append(r)
        if a.get('patch_candidate'):  by_priority_flag['patch'].append(r)

    total_cost = results_manager.total_cost()

    def result_rows(items):
        rows = ''
        for r in items:
            a = r.get('analysis', {})
            name = a.get('name', r['name'])
            desc = a.get('description', '—')[:100]
            sub = a.get('subsystem', '?')
            conf = a.get('confidence', '?')
            addr = r.get('address', '?')
            flags = ''
            if a.get('safedisc_related'): flags += '<span class="flag sd">SafeDisc</span>'
            if a.get('gamespy_related'):  flags += '<span class="flag gs">GameSpy</span>'
            if a.get('memory_related'):   flags += '<span class="flag mem">Memory</span>'
            if a.get('patch_candidate'):  flags += '<span class="flag patch">Patch</span>'
            conf_color = '#50b860' if conf == 'high' else '#d4b820' if conf == 'medium' else '#e08020'
            rows += f'''<tr>
                <td style="color:#e8d5a0;font-size:11px;font-weight:700">{r["name"]}</td>
                <td style="color:var(--text-dim);font-size:10px">{addr}</td>
                <td style="color:var(--gold);font-size:11px">{name}</td>
                <td style="color:var(--text-dim);font-size:11px">{desc}</td>
                <td style="color:var(--blue);font-size:11px">{sub}</td>
                <td>{flags}</td>
                <td style="color:{conf_color};font-size:10px">{conf}</td>
            </tr>'''
        return rows

    # Subsystem summary
    sub_rows = ''
    for sub, items in sorted(by_subsystem.items(), key=lambda x: -len(x[1])):
        sub_rows += f'<tr><td style="color:var(--blue)">{sub}</td><td style="color:var(--orange)">{len(items)}</td></tr>'

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>DS2 AI Analysis Results</title>
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
       padding:10px 18px;text-align:center;min-width:110px}}
.sv{{font-size:20px;font-weight:700}}
.sl{{color:var(--text-dim);font-size:10px;font-family:'Cinzel',serif;letter-spacing:1px;margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}}
th{{background:var(--bg3);color:var(--gold-dim);padding:7px 10px;text-align:left;
    border-bottom:2px solid var(--border);font-family:'Cinzel',serif;font-size:10px;letter-spacing:1px}}
td{{padding:5px 10px;border-bottom:1px solid var(--bg3);vertical-align:middle}}
tr:hover td{{background:var(--bg2)}}
.flag{{display:inline-block;font-size:9px;padding:1px 5px;border-radius:2px;margin:1px;white-space:nowrap}}
.flag.sd{{background:#200808;color:#ff6060;border:1px solid #400808}}
.flag.gs{{background:#080818;color:#6080ff;border:1px solid #101840}}
.flag.mem{{background:#180808;color:#ff8040;border:1px solid #401808}}
.flag.patch{{background:#081808;color:#40c060;border:1px solid #103010}}
</style></head><body>
<div class="hdr">
  <h1>⚔ DS2 AI ANALYSIS RESULTS</h1>
  <div class="sub">{datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;|&nbsp;
  {len(results)} functions analyzed &nbsp;|&nbsp; Total cost: ${total_cost:.4f} USD</div>
</div>
<div class="main">

<h2>SUMMARY</h2>
<div class="stats">
  <div class="stat"><div class="sv" style="color:var(--green)">{len(results)}</div><div class="sl">ANALYZED</div></div>
  <div class="stat"><div class="sv" style="color:var(--red)">{len(by_priority_flag["safedisc"])}</div><div class="sl">SAFEDISC</div></div>
  <div class="stat"><div class="sv" style="color:var(--blue)">{len(by_priority_flag["gamespy"])}</div><div class="sl">GAMESPY</div></div>
  <div class="stat"><div class="sv" style="color:var(--orange)">{len(by_priority_flag["memory"])}</div><div class="sl">MEMORY</div></div>
  <div class="stat"><div class="sv" style="color:var(--yellow)">{len(by_priority_flag["patch"])}</div><div class="sl">PATCH TARGETS</div></div>
  <div class="stat"><div class="sv" style="color:var(--gold)">${total_cost:.4f}</div><div class="sl">COST USD</div></div>
</div>

<h2>SUBSYSTEM BREAKDOWN</h2>
<table style="width:300px">
  <tr><th>SUBSYSTEM</th><th>COUNT</th></tr>
  {sub_rows}
</table>

<h2>PATCH CANDIDATES — Functions needing modification</h2>
<table>
  <tr><th>ORIGINAL NAME</th><th>ADDRESS</th><th>SUGGESTED NAME</th><th>DESCRIPTION</th><th>SUBSYSTEM</th><th>FLAGS</th><th>CONFIDENCE</th></tr>
  {result_rows(by_priority_flag["patch"]) or '<tr><td colspan="7" style="color:var(--text-faint)">None identified yet</td></tr>'}
</table>

<h2>GAMESPY / MULTIPLAYER FUNCTIONS</h2>
<table>
  <tr><th>ORIGINAL NAME</th><th>ADDRESS</th><th>SUGGESTED NAME</th><th>DESCRIPTION</th><th>SUBSYSTEM</th><th>FLAGS</th><th>CONFIDENCE</th></tr>
  {result_rows(by_priority_flag["gamespy"]) or '<tr><td colspan="7" style="color:var(--text-faint)">None identified yet</td></tr>'}
</table>

<h2>ALL ANALYZED FUNCTIONS</h2>
<table>
  <tr><th>ORIGINAL NAME</th><th>ADDRESS</th><th>SUGGESTED NAME</th><th>DESCRIPTION</th><th>SUBSYSTEM</th><th>FLAGS</th><th>CONFIDENCE</th></tr>
  {result_rows(results)}
</table>

</div></body></html>'''

    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"  [html] {REPORT_FILE}")


# ── Ghidra script generator ────────────────────────────────────────────────────

def make_ghidra_script(results_manager):
    """Generate a Ghidra Python script to apply analysis results as comments."""
    results = list(results_manager.results.values())
    if not results:
        return

    lines = [
        '# DS2 AI Analysis Results — Ghidra Comment Applier',
        '# Generated: ' + datetime.now().isoformat(),
        '# Run in Ghidra: Window → Script Manager → Run Script',
        '',
        'from ghidra.program.model.address import Address',
        'from ghidra.app.cmd.label import SetLabelPrimaryCmd',
        '',
        'listing = currentProgram.getListing()',
        'symbolTable = currentProgram.getSymbolTable()',
        'addressFactory = currentProgram.getAddressFactory()',
        '',
        'results = [',
    ]

    for r in results:
        a = r.get('analysis', {})
        addr = r.get('address', '').replace('0x', '')
        if not addr or addr == '?':
            continue
        name = a.get('name', '').replace('"', '\\"')
        desc = a.get('description', '').replace('"', '\\"')[:120]
        sub = a.get('subsystem', 'unknown')
        conf = a.get('confidence', 'low')
        lines.append(f'    {{"addr": "0x{addr}", "name": "{name}", "desc": "{desc}", "sub": "{sub}", "conf": "{conf}"}},')

    lines += [
        ']',
        '',
        'applied = 0',
        'for r in results:',
        '    try:',
        '        addr = addressFactory.getAddress(r["addr"])',
        '        func = listing.getFunctionAt(addr)',
        '        if func:',
        '            # Set function name if it looks meaningful',
        '            if r["name"] and r["name"] != "unknown" and "_" in r["name"]:',
        '                func.setName(r["name"], ghidra.program.model.symbol.SourceType.ANALYSIS)',
        '            # Add plate comment with description',
        '            if r["desc"]:',
        '                listing.setComment(addr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,',
        '                    "[AI] " + r["desc"] + " [" + r["conf"] + " confidence]")',
        '            applied += 1',
        '    except Exception as e:',
        '        print("Error at " + r["addr"] + ": " + str(e))',
        '',
        'print("Applied " + str(applied) + " annotations")',
    ]

    with open(GHIDRA_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"  [py]   {GHIDRA_FILE}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DS2 AI Function Analyzer')
    ap.add_argument('--dir',          default='.', help='Directory with C export files')
    ap.add_argument('--queue',        default=None, help='Priority queue JSON from ds2_survey.py')
    ap.add_argument('--diff',         default=None, help='Diff HTML report to load queue from')
    ap.add_argument('--limit',        type=int, default=50, help='Max functions to analyze (default: 50)')
    ap.add_argument('--preview',      action='store_true', help='Show cost estimate only, no API calls')
    ap.add_argument('--batch',        action='store_true', help='No confirmations, run to completion')
    ap.add_argument('--results',      action='store_true', help='Show existing results and exit')
    ap.add_argument('--report',       action='store_true', help='Generate HTML report from existing results')
    ap.add_argument('--critical-only',action='store_true', help='Only analyze CRITICAL functions')
    ap.add_argument('--ollama-model', default=None, help='Override Ollama model (e.g. mistral, codellama)')
    ap.add_argument('--use-api',      action='store_true', help='Force use Anthropic API instead of Ollama')
    args = ap.parse_args()

    print(f"\n{'='*55}")
    print(f"  DS2 AI FUNCTION ANALYZER")
    print(f"{'='*55}\n")

    # Load existing results
    rm = ResultsManager()

    if args.results or args.report:
        make_report(rm)
        make_ghidra_script(rm)
        print(f"\n  {len(rm.results)} results, ${rm.total_cost():.4f} spent so far")
        return

    # Detect backend
    if args.use_api:
        backend, model = 'anthropic', MODEL
    elif args.ollama_model:
        backend, model = 'ollama', args.ollama_model
    else:
        backend, model = detect_backend()

    print(f"  Backend detection:")
    if backend == 'ollama':
        models = ollama_list_models()
        print(f"    Ollama: RUNNING ✓")
        print(f"    Available models: {', '.join(models)}")
        print(f"    Selected: {model}")
        print(f"    Cost: FREE (local)")
    elif backend == 'anthropic':
        print(f"    Ollama: not running")
        print(f"    Anthropic API: available ✓")
        print(f"    Model: {model}")
    else:
        print(f"    Ollama: not running")
        print(f"    Anthropic API: not configured")
        print(f"\n  To use Ollama (recommended — free):")
        print(f"    1. Make sure Ollama is running: ollama serve")
        print(f"    2. Pull a model: ollama pull mistral")
        print(f"    3. Re-run this script")
        print(f"\n  To use Anthropic API:")
        print(f"    set ANTHROPIC_API_KEY=your_key_here")
        if not args.preview:
            sys.exit(1)

    # Load queue
    queue = []
    if args.queue and os.path.exists(args.queue):
        queue = load_queue_from_json(args.queue)
        print(f"\n  Queue loaded from JSON: {len(queue)} functions")
    elif args.diff and os.path.exists(args.diff):
        queue = load_queue_from_diff(args.diff)
        print(f"\n  Queue loaded from diff: {len(queue)} functions")
    else:
        for f in ['ds2_priority_queue.json', 'ds2_diff_report.html']:
            if os.path.exists(f):
                if f.endswith('.json'):
                    queue = load_queue_from_json(f)
                else:
                    queue = load_queue_from_diff(f)
                print(f"\n  Auto-detected queue: {f} ({len(queue)} functions)")
                break

    if not queue:
        print("  No queue found. Run ds2_survey.py first, or specify --queue or --diff")
        sys.exit(1)

    if args.critical_only:
        queue = [i for i in queue if i['priority'] == 'CRITICAL']
        print(f"  Filtered to CRITICAL only: {len(queue)} functions")

    # Preview
    pending, est_cost = preview_cost(queue, args.limit, set(rm.results.keys()))

    if backend == 'ollama':
        print(f"\n  Using Ollama — this is FREE regardless of function count")
        print(f"  Estimated time: ~{len(pending) * 15 // 60}min {len(pending) * 15 % 60}s "
              f"(~15s per function with {model})")

    if args.preview:
        return

    if not pending:
        print("\n  Nothing to analyze — all queued functions already processed.")
        make_report(rm)
        return

    if not args.batch:
        cost_str = "FREE (Ollama)" if backend == 'ollama' else f"~${est_cost:.2f} USD"
        print(f"\n  Ready to analyze {len(pending)} functions ({cost_str})")
        confirm = input("  Type YES to proceed: ")
        if confirm.strip().upper() != 'YES':
            print("  Cancelled.")
            return

    # Run
    analyzer = DS2Analyzer(args.dir, rm, backend=backend, model=model)

    print(f"\n{'='*55}")
    print(f"  ANALYZING {len(pending)} FUNCTIONS")
    print(f"{'='*55}\n")

    success = 0
    failed = 0
    skipped = 0
    start_time = time.time()

    for i, item in enumerate(pending):
        name = item['name']
        addr = item.get('address', '?')
        priority = item.get('priority', '?')
        diff_pct = int(item.get('diff_score', 1.0) * 100)

        print(f"  [{i+1}/{len(pending)}] {name} ({priority}, {diff_pct}% similar)...")

        body, source = analyzer.get_body(name)
        if not body:
            print(f"    [skip] No body found in exports")
            skipped += 1
            continue

        analysis, prompt_tokens, completion_tokens = analyzer.analyze_function(item)

        if analysis:
            rm.add(name, addr, analysis, str(analysis), prompt_tokens, completion_tokens)
            rm.save()
            success += 1

            suggested_name = analysis.get('name', '?')
            desc = analysis.get('description', '')[:70]
            if backend == 'ollama':
                cost_str = 'free'
            else:
                cost = (prompt_tokens * INPUT_COST_PER_M / 1_000_000) + \
                       (completion_tokens * OUTPUT_COST_PER_M / 1_000_000)
                cost_str = f'${cost:.4f}'

            print(f"    ✓ {suggested_name}")
            print(f"      {desc}")
            print(f"      tokens: {prompt_tokens}+{completion_tokens} ({cost_str})")

            flags = []
            if analysis.get('safedisc_related'): flags.append('SafeDisc')
            if analysis.get('gamespy_related'):  flags.append('GameSpy')
            if analysis.get('patch_candidate'):  flags.append('PATCH TARGET')
            if flags:
                print(f"      ★ {', '.join(flags)}")
        else:
            print(f"    ✗ Failed")
            failed += 1

        # Small delay to avoid hammering Ollama
        time.sleep(0.2)

        if (i + 1) % 10 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed * 60 if elapsed > 0 else 0
            remaining = len(pending) - (i + 1)
            eta_min = remaining / rate if rate > 0 else 0
            cost_info = "FREE" if backend == 'ollama' else f"${rm.total_cost():.4f}"
            print(f"\n  Progress: {i+1}/{len(pending)} | Cost: {cost_info} | "
                  f"Rate: {rate:.0f}/min | ETA: {eta_min:.0f}min\n")

    elapsed = time.time() - start_time
    print(f"\n{'='*55}")
    print(f"  COMPLETE")
    print(f"{'='*55}")
    print(f"  Analyzed:  {success}")
    print(f"  Failed:    {failed}")
    print(f"  Skipped:   {skipped}")
    print(f"  Time:      {elapsed:.0f}s")
    if backend == 'anthropic':
        print(f"  Cost:      ${rm.total_cost():.4f} USD")
    else:
        print(f"  Cost:      FREE (Ollama)")

    print(f"\n  Generating outputs...")
    make_report(rm)
    make_ghidra_script(rm)
    print(f"\n  {RESULTS_FILE}  — resumable checkpoint")
    print(f"  {REPORT_FILE}   — visual report")
    print(f"  {GHIDRA_FILE}   — apply to Ghidra")
    print(f"\n  Ghidra: Window → Script Manager → Run Script → {GHIDRA_FILE}")


if __name__ == '__main__':
    main()
