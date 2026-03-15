#!/usr/bin/env python3
"""
DS2 GameSpy Protocol Sniffer
==============================
Captures and decodes DS2 multiplayer network traffic.
Specifically designed to decode the GameSpy \\key\\value\\final\\ protocol.

Run as Administrator BEFORE launching DS2.

Usage:
    python ds2_sniffer.py                    # Sniff all DS2 traffic
    python ds2_sniffer.py --log output.txt   # Save to file
    python ds2_sniffer.py --replay file.txt  # Replay/analyze saved capture

Ports monitored:
    29900  GameSpy Presence & Messaging (login/auth)
    29920  DS2 custom port (unknown — this is what we're finding out)
    6500   GameSpy server browser (game list)
    6515   CD key verification
    27900  GameSpy master server
    3783   GameSpy voice
    28910  NAT negotiation

Requires:
    pip install scapy --break-system-packages
    OR falls back to raw socket capture if scapy not available
    Must run as Administrator on Windows
"""

import os
import sys
import json
import time
import socket
import struct
import threading
import argparse
from datetime import datetime
from collections import defaultdict

# Try scapy first, fall back to raw socket
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ── GameSpy ports of interest ─────────────────────────────────────────────────

PORTS = {
    29900: 'GP Presence/Messaging (login)',
    29901: 'GP Search',
    29920: 'DS2 Custom (unknown)',
    6500:  'Server Browser (game list)',
    6515:  'CD Key Verification',
    27900: 'Master Server',
    27901: 'Master Server Alt',
    28910: 'NAT Negotiation',
    3783:  'Voice Chat',
    # Common game ports
    2302:  'DS2 Game Port (possible)',
    2303:  'DS2 Query Port (possible)',
}

# Known GameSpy commands and their meanings
GAMESPY_COMMANDS = {
    # Client → Server
    'login':        'Player login request',
    'newuser':      'Register new account',
    'auth':         'Authentication',
    'authp':        'Authentication with profile',
    'ka':           'Keep-alive ping',
    'status':       'Set player status',
    'bm':           'Buddy message',
    'addbuddy':     'Add friend',
    'delbuddy':     'Remove friend',
    'getprofile':   'Request profile info',
    'updatepro':    'Update profile',
    'newgame':      'Create game session',
    'updgame':      'Update game session',
    'endgame':      'End game session',
    'setlocalip':   'Set local IP for NAT',
    'initiate':     'Initiate P2P connection',

    # Server → Client
    'lc':           'Login challenge (server sends)',
    'lr':           'Login response',
    'pi':           'Profile info response',
    'bdy':          'Buddy list',
    'bm':           'Buddy message received',
    'error':        'Error response',
    'peerport':     'Peer port for NAT',

    # Server browser
    'gamename':     'Game identifier (dsiege2)',
    'hostname':     'Server hostname',
    'hostport':     'Server port',
    'mapname':      'Current map',
    'gamever':      'Game version',
    'numplayers':   'Current player count',
    'maxplayers':   'Max players',
    'gamemode':     'Game mode',
    'password':     'Password protected',

    # DS2 specific (guesses based on game)
    'final':        'End of packet marker',
    'productid':    'DS2 product ID (10609)',
    'namespaceid':  'Namespace ID',
    'uniquenick':   'Unique nickname',
    'passwordenc':  'Encrypted password',
}


# ── GameSpy packet decoder ────────────────────────────────────────────────────

def decode_gamespy(data, direction='→'):
    """Decode GameSpy \\key\\value\\final\\ format packets."""
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        return None

    # Check if it looks like GameSpy format
    if '\\' not in text:
        return None

    parts = text.split('\\')
    if len(parts) < 3:
        return None

    result = {
        'raw': text,
        'direction': direction,
        'pairs': {},
        'command': None,
        'known_fields': {},
        'unknown_fields': {},
    }

    # Parse key\value pairs
    i = 1  # skip leading empty string from split
    while i < len(parts) - 1:
        key = parts[i].strip()
        val = parts[i+1].strip() if i+1 < len(parts) else ''
        if key:
            result['pairs'][key] = val
            if key in GAMESPY_COMMANDS:
                result['known_fields'][key] = {
                    'value': val,
                    'meaning': GAMESPY_COMMANDS[key]
                }
            else:
                result['unknown_fields'][key] = val
        i += 2

    # Identify command (usually first key)
    if parts and len(parts) > 1:
        first_key = parts[1].strip() if len(parts) > 1 else ''
        result['command'] = first_key
        result['command_desc'] = GAMESPY_COMMANDS.get(first_key, 'Unknown command')

    return result


def format_gamespy(decoded, src, dst, port, proto):
    """Format a decoded GameSpy packet for display."""
    if not decoded:
        return None

    lines = []
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    direction_arrow = '→ SEND' if decoded['direction'] == '→' else '← RECV'

    port_name = PORTS.get(port, f'port {port}')
    cmd = decoded.get('command', '?')
    cmd_desc = decoded.get('command_desc', '')

    lines.append(f"\n{'─'*60}")
    lines.append(f"  [{ts}] {direction_arrow}  {proto} {src} → {dst}")
    lines.append(f"  Port: {port} ({port_name})")
    lines.append(f"  Command: \\{cmd}\\ — {cmd_desc}")
    lines.append(f"{'─'*60}")

    # Show known fields first
    if decoded['known_fields']:
        lines.append("  Known fields:")
        for key, info in decoded['known_fields'].items():
            val = info['value']
            meaning = info['meaning']
            # Mask passwords
            if 'password' in key.lower():
                val = '*' * len(val)
            lines.append(f"    \\{key}\\ = {val!r:30s} ← {meaning}")

    # Show unknown fields
    if decoded['unknown_fields']:
        lines.append("  Unknown fields (new protocol elements):")
        for key, val in decoded['unknown_fields'].items():
            lines.append(f"    \\{key}\\ = {val!r}  ← ??? DOCUMENT THIS")

    # Special handling for interesting values
    pairs = decoded['pairs']
    if 'gamename' in pairs:
        lines.append(f"\n  ★ Game identifier: {pairs['gamename']}")
    if 'productid' in pairs:
        lines.append(f"  ★ Product ID: {pairs['productid']}")
    if 'final' in text_from_decoded(decoded):
        lines.append(f"  ★ Packet complete (\\final\\ marker present)")

    return '\n'.join(lines)


def text_from_decoded(decoded):
    return decoded.get('raw', '')


# ── Raw data analyzer ─────────────────────────────────────────────────────────

def analyze_raw(data, src, dst, port, proto, direction):
    """Analyze raw packet data for any DS2 protocol patterns."""
    result = {
        'timestamp': datetime.now().isoformat(),
        'src': src,
        'dst': dst,
        'port': port,
        'proto': proto,
        'direction': direction,
        'size': len(data),
        'gamespy': None,
        'raw_hex': data.hex()[:128],
        'raw_text': '',
        'interesting': False,
        'notes': [],
    }

    # Try text decode
    try:
        text = data.decode('utf-8', errors='replace')
        result['raw_text'] = text[:500]
    except Exception:
        pass

    # Try GameSpy decode
    gs = decode_gamespy(data, direction)
    if gs:
        result['gamespy'] = gs
        result['interesting'] = True
        result['notes'].append(f"GameSpy protocol: \\{gs['command']}\\")

    # Check for other interesting patterns
    if b'dsiege2' in data:
        result['interesting'] = True
        result['notes'].append('Contains game identifier: dsiege2')
    if b'10609' in data:
        result['interesting'] = True
        result['notes'].append('Contains DS2 product ID: 10609')
    if b'final' in data.lower():
        result['interesting'] = True
        result['notes'].append('Contains \\final\\ marker')

    # Binary protocol detection (non-GameSpy)
    if not gs and len(data) >= 4:
        # Check for common binary protocol headers
        header = struct.unpack_from('>HH', data[:4]) if len(data) >= 4 else (0,0)
        result['notes'].append(f'Binary header: 0x{data[:4].hex()} ({header})')

    return result


# ── Scapy sniffer ─────────────────────────────────────────────────────────────

class DS2Sniffer:
    def __init__(self, log_file=None):
        self.log_file = log_file
        self.captured = []
        self.stats = defaultdict(int)
        self.session_map = {}  # track connection sessions
        self.start_time = time.time()
        self.lock = threading.Lock()

        if log_file:
            self.log_fh = open(log_file, 'w', encoding='utf-8')
        else:
            self.log_fh = None

    def output(self, text):
        print(text)
        if self.log_fh:
            self.log_fh.write(text + '\n')
            self.log_fh.flush()

    def process_packet(self, pkt):
        """Process a captured packet."""
        try:
            if IP not in pkt:
                return
            if Raw not in pkt:
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            data = bytes(pkt[Raw])

            if TCP in pkt:
                proto = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            else:
                return

            # Check if either port is interesting
            interesting_port = None
            direction = '→'

            if dst_port in PORTS:
                interesting_port = dst_port
                direction = '→'
            elif src_port in PORTS:
                interesting_port = src_port
                direction = '←'
            else:
                return

            src = f"{src_ip}:{src_port}"
            dst = f"{dst_ip}:{dst_port}"

            self.stats[interesting_port] += 1
            self.stats['total'] += 1

            analysis = analyze_raw(data, src, dst, interesting_port, proto, direction)

            with self.lock:
                self.captured.append(analysis)

            # Display
            port_name = PORTS.get(interesting_port, str(interesting_port))
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            dir_str = '→ SEND' if direction == '→' else '← RECV'

            if analysis['gamespy']:
                gs = analysis['gamespy']
                cmd = gs.get('command', '?')
                self.output(f"\n{'='*60}")
                self.output(f"  [{ts}] {dir_str} {proto} | Port {interesting_port} ({port_name})")
                self.output(f"  {src} → {dst}")
                self.output(f"  GameSpy Command: \\{cmd}\\ — {GAMESPY_COMMANDS.get(cmd, 'UNKNOWN — document this!')}")
                self.output(f"{'─'*60}")

                for key, val in gs['pairs'].items():
                    meaning = GAMESPY_COMMANDS.get(key, '??? NEW FIELD')
                    if 'password' in key.lower():
                        val = '***MASKED***'
                    flag = '  ★' if key not in GAMESPY_COMMANDS else '   '
                    self.output(f"{flag} \\{key}\\ = {val!r:35s} | {meaning}")

                if gs['unknown_fields']:
                    self.output(f"\n  ⚠ UNKNOWN FIELDS — add to protocol documentation:")
                    for k, v in gs['unknown_fields'].items():
                        self.output(f"    \\{k}\\ = {v!r}")

            else:
                # Non-GameSpy but on interesting port
                self.output(f"\n[{ts}] {dir_str} {proto} port {interesting_port} ({port_name})"
                           f" | {len(data)} bytes")
                if analysis['notes']:
                    for note in analysis['notes']:
                        self.output(f"  → {note}")
                # Show hex for binary protocols
                self.output(f"  Hex: {data[:32].hex()} {'...' if len(data)>32 else ''}")
                if analysis['raw_text']:
                    printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in analysis['raw_text'][:80])
                    self.output(f"  Text: {printable}")

        except Exception as e:
            pass  # Don't crash on malformed packets

    def print_stats(self):
        elapsed = time.time() - self.start_time
        self.output(f"\n{'='*60}")
        self.output(f"  CAPTURE STATS ({elapsed:.0f}s)")
        self.output(f"{'='*60}")
        self.output(f"  Total packets: {self.stats['total']}")
        for port, count in sorted(self.stats.items()):
            if port == 'total': continue
            name = PORTS.get(port, str(port))
            self.output(f"  Port {port:5d} ({name}): {count} packets")

    def save_json(self, path):
        with open(path, 'w') as f:
            json.dump(self.captured, f, indent=2, default=str)
        self.output(f"\n  Saved {len(self.captured)} packets to {path}")

    def close(self):
        if self.log_fh:
            self.log_fh.close()


# ── Raw socket fallback ────────────────────────────────────────────────────────

def raw_socket_sniff(sniffer, interface=None):
    """
    Fallback sniffer using raw sockets when Scapy is not available.
    Limited but functional for TCP traffic analysis.
    """
    print("  Using raw socket capture (limited — install scapy for full capture)")
    print("  pip install scapy")
    print()

    try:
        # Create raw socket
        if sys.platform == 'win32':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind(('0.0.0.0', 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

        sock.settimeout(1.0)

        while True:
            try:
                raw_data, addr = sock.recvfrom(65535)
                # Parse IP header
                if len(raw_data) < 20:
                    continue
                ip_header = raw_data[:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                ip_len = (iph[0] & 0xF) * 4

                if protocol == 6:  # TCP
                    if len(raw_data) < ip_len + 20:
                        continue
                    tcp_header = raw_data[ip_len:ip_len+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    src_port = tcph[0]
                    dst_port = tcph[1]
                    tcp_len = (tcph[4] >> 4) * 4
                    data = raw_data[ip_len + tcp_len:]
                    proto = 'TCP'
                elif protocol == 17:  # UDP
                    if len(raw_data) < ip_len + 8:
                        continue
                    udp_header = raw_data[ip_len:ip_len+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    src_port = udph[0]
                    dst_port = udph[1]
                    data = raw_data[ip_len+8:]
                    proto = 'UDP'
                else:
                    continue

                if not data:
                    continue

                # Check ports
                if dst_port in PORTS or src_port in PORTS:
                    port = dst_port if dst_port in PORTS else src_port
                    direction = '→' if dst_port in PORTS else '←'
                    src = f"{src_ip}:{src_port}"
                    dst = f"{dst_ip}:{dst_port}"

                    analysis = analyze_raw(data, src, dst, port, proto, direction)
                    sniffer.captured.append(analysis)
                    sniffer.stats[port] += 1
                    sniffer.stats['total'] += 1

                    # Display
                    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    port_name = PORTS.get(port, str(port))
                    dir_str = '→ SEND' if direction == '→' else '← RECV'

                    if analysis['gamespy']:
                        gs = analysis['gamespy']
                        cmd = gs.get('command', '?')
                        print(f"\n{'='*60}")
                        print(f"  [{ts}] {dir_str} {proto} | Port {port} ({port_name})")
                        print(f"  GameSpy: \\{cmd}\\ — {GAMESPY_COMMANDS.get(cmd, 'UNKNOWN')}")
                        for key, val in gs['pairs'].items():
                            meaning = GAMESPY_COMMANDS.get(key, '??? NEW')
                            if 'password' in key.lower():
                                val = '***'
                            print(f"    \\{key}\\ = {val!r:30s} | {meaning}")
                    else:
                        print(f"  [{ts}] {dir_str} {proto}:{port} ({port_name}) {len(data)}b | {data[:32].hex()}")

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

    except PermissionError:
        print("\n  ERROR: Must run as Administrator for raw socket capture")
        print("  Right-click PowerShell → Run as Administrator")
        return
    except Exception as e:
        print(f"\n  Socket error: {e}")
    finally:
        try:
            if sys.platform == 'win32':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        except Exception:
            pass


# ── Replay/analyze saved capture ──────────────────────────────────────────────

def replay_capture(filepath):
    """Analyze a previously saved capture JSON."""
    print(f"\n  Analyzing capture: {filepath}")

    with open(filepath) as f:
        packets = json.load(f)

    print(f"  {len(packets)} packets loaded\n")

    port_summary = defaultdict(list)
    commands_seen = defaultdict(int)
    unknown_fields = defaultdict(set)
    protocol_sequence = []

    for pkt in packets:
        port = pkt.get('port')
        port_name = PORTS.get(port, str(port))
        gs = pkt.get('gamespy')

        if gs:
            cmd = gs.get('command', '?')
            commands_seen[cmd] += 1
            protocol_sequence.append({
                'port': port,
                'port_name': port_name,
                'direction': pkt['direction'],
                'command': cmd,
                'pairs': gs.get('pairs', {}),
            })
            for k in gs.get('unknown_fields', {}):
                unknown_fields[k].add(gs['unknown_fields'][k])

        port_summary[port].append(pkt)

    # Print protocol sequence
    print(f"{'='*60}")
    print(f"  PROTOCOL SEQUENCE")
    print(f"{'='*60}")
    for i, step in enumerate(protocol_sequence):
        dir_str = '→ C→S' if step['direction'] == '→' else '← S→C'
        cmd = step['command']
        port = step['port']
        print(f"  {i+1:3d}. [{dir_str}] port {port:5d} | \\{cmd}\\ — {GAMESPY_COMMANDS.get(cmd, 'UNKNOWN')}")

    print(f"\n{'='*60}")
    print(f"  COMMANDS SEEN")
    print(f"{'='*60}")
    for cmd, count in sorted(commands_seen.items(), key=lambda x: -x[1]):
        print(f"  \\{cmd}\\ × {count:3d} — {GAMESPY_COMMANDS.get(cmd, '??? UNKNOWN — document this')}")

    if unknown_fields:
        print(f"\n{'='*60}")
        print(f"  UNKNOWN PROTOCOL FIELDS — Need Documentation")
        print(f"{'='*60}")
        for field, values in sorted(unknown_fields.items()):
            print(f"  \\{field}\\ — seen values: {list(values)[:5]}")

    print(f"\n{'='*60}")
    print(f"  PORT ACTIVITY")
    print(f"{'='*60}")
    for port, pkts in sorted(port_summary.items()):
        print(f"  Port {port:5d} ({PORTS.get(port,'?'):35s}): {len(pkts)} packets")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='DS2 GameSpy Protocol Sniffer')
    ap.add_argument('--log',    default=None, help='Log output to file')
    ap.add_argument('--json',   default='ds2_capture.json', help='Save packets as JSON')
    ap.add_argument('--replay', default=None, help='Analyze a saved capture JSON')
    ap.add_argument('--iface',  default=None, help='Network interface to sniff')
    ap.add_argument('--timeout',type=int, default=120, help='Capture timeout seconds (default 120)')
    args = ap.parse_args()

    if args.replay:
        replay_capture(args.replay)
        return

    print(f"\n{'='*60}")
    print(f"  DS2 GAMESPY PROTOCOL SNIFFER")
    print(f"{'='*60}")
    print(f"  Monitoring ports: {', '.join(str(p) for p in PORTS)}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Output: {args.json}")
    if args.log:
        print(f"  Log: {args.log}")
    print(f"\n  ► Launch DS2 and go to the Multiplayer menu now")
    print(f"  ► Try to connect to a server or host a game")
    print(f"  ► Press Ctrl+C to stop capture early")
    print(f"{'='*60}\n")

    sniffer = DS2Sniffer(log_file=args.log)

    try:
        if HAS_SCAPY:
            print("  Using Scapy for full packet capture\n")
            port_filter = ' or '.join(f'port {p}' for p in PORTS)
            sniff(
                filter=port_filter,
                prn=sniffer.process_packet,
                timeout=args.timeout,
                iface=args.iface,
                store=False,
            )
        else:
            print("  Scapy not found — using raw socket fallback")
            print("  For best results: pip install scapy\n")
            raw_socket_sniff(sniffer, args.iface)

    except KeyboardInterrupt:
        print("\n\n  Capture stopped by user")
    except Exception as e:
        print(f"\n  Error: {e}")
        if 'permission' in str(e).lower() or 'admin' in str(e).lower():
            print("  → Run as Administrator")

    finally:
        sniffer.print_stats()
        if sniffer.captured:
            sniffer.save_json(args.json)
            print(f"\n  To analyze later:")
            print(f"  python ds2_sniffer.py --replay {args.json}")
        sniffer.close()


if __name__ == '__main__':
    main()
