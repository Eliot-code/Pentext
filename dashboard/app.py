#!/usr/bin/env python3
"""
AutoPentestX — Web Dashboard
==============================
Lightweight Flask dashboard providing:
  • Live scan status via Server-Sent Events (SSE)
  • Attack path graph (pure-JS SVG force-directed, no D3)
  • Findings table with severity filtering
  • C2 session overview (read-only)
  • PDF report download

Run:
  python dashboard/app.py [--host 0.0.0.0] [--port 5000] [--db database/autopentestx.db]
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from flask import Flask, Response, jsonify, render_template, request, send_file
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

DB_PATH   = os.environ.get('APX_DB',   'database/autopentestx.db')
C2_DB     = os.environ.get('APX_C2DB', 'database/c2.sqlite')
REPORT_DIR = os.environ.get('APX_REPORTS', 'reports')


# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _query(db_path: str, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    if not os.path.exists(db_path):
        return []
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_scans() -> List[Dict[str, Any]]:
    return _query(DB_PATH,
        'SELECT id, target, scan_date, status, risk_score, open_ports, '
        'vulnerabilities_found, scan_duration FROM scans ORDER BY scan_date DESC LIMIT 50')


def get_vulnerabilities(scan_id: int) -> List[Dict[str, Any]]:
    return _query(DB_PATH,
        'SELECT * FROM vulnerabilities WHERE scan_id=? ORDER BY cvss_score DESC', (scan_id,))


def get_web_vulns(scan_id: int) -> List[Dict[str, Any]]:
    return _query(DB_PATH,
        'SELECT * FROM web_vulnerabilities WHERE scan_id=?', (scan_id,))


def get_ports(scan_id: int) -> List[Dict[str, Any]]:
    return _query(DB_PATH,
        'SELECT * FROM ports WHERE scan_id=?', (scan_id,))


def get_c2_sessions() -> List[Dict[str, Any]]:
    return _query(C2_DB,
        'SELECT id, host, user, os, arch, pid, external_ip, internal_ip, '
        'registered_at, last_seen_at, sleep_seconds FROM sessions ORDER BY last_seen_at DESC')


def get_c2_results(sid: str) -> List[Dict[str, Any]]:
    return _query(C2_DB,
        'SELECT r.id, r.task_id, r.output, r.received_at, t.kind, t.payload '
        'FROM results r JOIN tasks t ON r.task_id = t.id '
        'WHERE r.session_id=? ORDER BY r.id DESC LIMIT 25', (sid,))


# ─────────────────────────────────────────────────────────────────────────────
#  ATTACK PATH GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    'CRITICAL': '#e74c3c',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#f1c40f',
    'LOW':      '#27ae60',
    'UNKNOWN':  '#95a5a6',
}

CHAIN_EDGES = {
    'SQL Injection':      ['Remote Code Execution', 'Data Exfiltration', 'Authentication Bypass'],
    'Command Injection':  ['Remote Code Execution', 'Lateral Movement'],
    'SSRF':               ['Internal Network Access', 'Cloud Metadata Exposure'],
    'Path Traversal':     ['Sensitive File Disclosure', 'Authentication Bypass'],
    'Stored XSS':         ['Session Hijacking', 'Credential Harvesting'],
    'Reflected XSS':      ['Session Hijacking'],
    'File Upload':        ['Remote Code Execution', 'Stored XSS'],
    'XXE':                ['SSRF', 'Sensitive File Disclosure'],
    'SSTI':               ['Remote Code Execution'],
    'Deserialization':    ['Remote Code Execution'],
    'Open Redirect':      ['Phishing / Credential Harvesting'],
}

IMPACT_COLORS = {
    'Remote Code Execution':           '#c0392b',
    'Data Exfiltration':               '#8e44ad',
    'Authentication Bypass':           '#e74c3c',
    'Lateral Movement':                '#d35400',
    'Internal Network Access':         '#2980b9',
    'Cloud Metadata Exposure':         '#16a085',
    'Sensitive File Disclosure':       '#7f8c8d',
    'Session Hijacking':               '#e91e63',
    'Credential Harvesting':           '#9b59b6',
    'Phishing / Credential Harvesting': '#795548',
    'Stored XSS':                      '#e67e22',
}


def build_attack_graph(scan_id: int) -> Dict[str, Any]:
    """
    Build a force-graph compatible {nodes, links} structure from findings.
    Node types: target (root), finding (vuln), impact (chain endpoint)
    """
    nodes: List[Dict] = []
    links: List[Dict] = []
    node_ids: Dict[str, int] = {}

    def _node(nid: str, label: str, ntype: str, color: str,
               severity: str = '', url: str = '', cvss: float = 0) -> int:
        if nid in node_ids:
            return node_ids[nid]
        idx = len(nodes)
        nodes.append({'id': nid, 'label': label, 'type': ntype,
                      'color': color, 'severity': severity,
                      'url': url, 'cvss': cvss, 'index': idx})
        node_ids[nid] = idx
        return idx

    scans = _query(DB_PATH, 'SELECT target FROM scans WHERE id=?', (scan_id,))
    target = scans[0]['target'] if scans else f'scan-{scan_id}'
    _node('__target__', target, 'target', '#2c3e50')

    vulns = get_vulnerabilities(scan_id) + get_web_vulns(scan_id)
    for v in vulns:
        vtype = (v.get('vuln_type') or v.get('name') or 'Unknown').strip()
        cvss  = float(v.get('cvss_score') or 0)
        sev   = v.get('risk_level') or v.get('severity') or 'UNKNOWN'
        url   = v.get('url') or v.get('endpoint') or ''
        param = v.get('parameter') or v.get('param') or ''
        port  = v.get('port', '')

        label = vtype
        if param:
            label += f'\n({param})'
        if port:
            label += f' :{port}'

        nid = f'finding_{vtype}_{url}_{param}'
        _node(nid, label, 'finding',
              SEVERITY_COLOR.get(sev, '#95a5a6'), sev, url, cvss)

        links.append({'source': '__target__', 'target': nid,
                      'label': f'CVSS {cvss:.1f}' if cvss else ''})

        for chain_target in CHAIN_EDGES.get(vtype, []):
            cid = f'impact_{chain_target}'
            _node(cid, chain_target, 'impact',
                  IMPACT_COLORS.get(chain_target, '#7f8c8d'))
            links.append({'source': nid, 'target': cid, 'label': 'leads to'})

    return {'nodes': nodes, 'links': links,
            'target': target, 'scan_id': scan_id}


# ─────────────────────────────────────────────────────────────────────────────
#  FLASK APP
# ─────────────────────────────────────────────────────────────────────────────
if HAS_FLASK:
    app = Flask(__name__, template_folder='templates', static_folder='static')

    @app.route('/')
    def index():
        scans = get_scans()
        return render_template('index.html', scans=scans)

    @app.route('/scan/<int:scan_id>')
    def scan_detail(scan_id: int):
        vulns     = get_vulnerabilities(scan_id)
        web_vulns = get_web_vulns(scan_id)
        ports     = get_ports(scan_id)
        return render_template('scan.html',
                               scan_id=scan_id,
                               vulns=vulns,
                               web_vulns=web_vulns,
                               ports=ports)

    @app.route('/api/scans')
    def api_scans():
        return jsonify(get_scans())

    @app.route('/api/scan/<int:scan_id>/vulns')
    def api_vulns(scan_id: int):
        return jsonify(get_vulnerabilities(scan_id) + get_web_vulns(scan_id))

    @app.route('/api/scan/<int:scan_id>/graph')
    def api_graph(scan_id: int):
        return jsonify(build_attack_graph(scan_id))

    @app.route('/api/scan/<int:scan_id>/ports')
    def api_ports(scan_id: int):
        return jsonify(get_ports(scan_id))

    @app.route('/api/c2/sessions')
    def api_c2_sessions():
        return jsonify(get_c2_sessions())

    @app.route('/api/c2/sessions/<sid>/results')
    def api_c2_results(sid: str):
        return jsonify(get_c2_results(sid))

    @app.route('/api/stream/<int:scan_id>')
    def sse_stream(scan_id: int):
        """Server-Sent Events: polls DB for changes, pushes updates."""
        def generate():
            last_count = -1
            for _ in range(120):    # max 2 min stream
                rows = get_vulnerabilities(scan_id) + get_web_vulns(scan_id)
                if len(rows) != last_count:
                    last_count = len(rows)
                    data = json.dumps({'vuln_count': len(rows),
                                       'scan_id': scan_id,
                                       'ts': time.time()})
                    yield f'data: {data}\n\n'
                time.sleep(1)
        return Response(generate(), mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache',
                                 'X-Accel-Buffering': 'no'})

    @app.route('/attack-graph/<int:scan_id>')
    def attack_graph(scan_id: int):
        return render_template('graph.html', scan_id=scan_id)

    @app.route('/c2')
    def c2_dashboard():
        sessions = get_c2_sessions()
        return render_template('c2.html', sessions=sessions)

    @app.route('/reports/<path:filename>')
    def serve_report(filename: str):
        report_dir = os.path.abspath(REPORT_DIR)
        return send_file(os.path.join(report_dir, filename))


# ─────────────────────────────────────────────────────────────────────────────
#  HTML TEMPLATES (embedded)
# ─────────────────────────────────────────────────────────────────────────────
_BASE_CSS = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --accent: #58a6ff; --danger: #e74c3c;
  --warn: #e67e22; --ok: #27ae60; --muted: #8b949e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font: 14px/1.6 'Fira Code', monospace; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.nav { background: var(--surface); border-bottom: 1px solid var(--border);
       padding: 12px 24px; display: flex; gap: 24px; align-items: center; }
.nav strong { color: var(--danger); font-size: 16px; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }
h1 { font-size: 20px; margin-bottom: 16px; color: var(--accent); }
h2 { font-size: 16px; margin: 24px 0 12px; color: var(--text); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: var(--surface); padding: 8px 12px; text-align: left;
     border-bottom: 2px solid var(--border); color: var(--muted); }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
tr:hover td { background: rgba(88,166,255,.04); }
.badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
.CRITICAL { background:#e74c3c22; color:#e74c3c; border:1px solid #e74c3c44; }
.HIGH     { background:#e67e2222; color:#e67e22; border:1px solid #e67e2244; }
.MEDIUM   { background:#f1c40f22; color:#f1c40f; border:1px solid #f1c40f44; }
.LOW      { background:#27ae6022; color:#27ae60; border:1px solid #27ae6044; }
.UNKNOWN  { background:#8b949e22; color:#8b949e; border:1px solid #8b949e44; }
.card { background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.stat { font-size: 28px; font-weight: bold; }
.grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:16px; }
"""

_INDEX_HTML = """<!doctype html>
<title>AutoPentestX Dashboard</title>
<style>""" + _BASE_CSS + """</style>
<nav class="nav">
  <strong>AutoPentestX</strong>
  <a href="/">Scans</a>
  <a href="/c2">C2 Sessions</a>
</nav>
<div class="container">
  <h1>Scan History</h1>
  <div class="grid" style="margin-bottom:24px">
    <div class="card">
      <div class="muted" style="color:var(--muted);font-size:12px">TOTAL SCANS</div>
      <div class="stat">{{ scans|length }}</div>
    </div>
    <div class="card">
      <div class="muted" style="color:var(--muted);font-size:12px">CRITICAL FINDINGS</div>
      <div class="stat" style="color:var(--danger)">
        {{ scans|selectattr('risk_score','equalto','CRITICAL')|list|length }}
      </div>
    </div>
  </div>
  <table>
    <tr>
      <th>#</th><th>Target</th><th>Date</th><th>Status</th>
      <th>Risk</th><th>Ports</th><th>Vulns</th><th>Duration</th><th>Actions</th>
    </tr>
    {% for s in scans %}
    <tr>
      <td>{{ s.id }}</td>
      <td><strong>{{ s.target }}</strong></td>
      <td>{{ s.scan_date[:19] if s.scan_date else '—' }}</td>
      <td>{{ s.status or '—' }}</td>
      <td><span class="badge {{ s.risk_score or 'UNKNOWN' }}">{{ s.risk_score or 'N/A' }}</span></td>
      <td>{{ s.open_ports or 0 }}</td>
      <td>{{ s.vulnerabilities_found or 0 }}</td>
      <td>{{ '%.1fs'|format(s.scan_duration) if s.scan_duration else '—' }}</td>
      <td>
        <a href="/scan/{{ s.id }}">Findings</a> ·
        <a href="/attack-graph/{{ s.id }}">Graph</a>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="9" style="color:var(--muted);text-align:center;padding:40px">
      No scans yet. Run: python main.py -t &lt;target&gt;
    </td></tr>
    {% endfor %}
  </table>
</div>
"""

_SCAN_HTML = """<!doctype html>
<title>Scan {{ scan_id }} — AutoPentestX</title>
<style>""" + _BASE_CSS + """
#filter { background:var(--surface); border:1px solid var(--border); color:var(--text);
          padding:6px 12px; border-radius:4px; margin-bottom:12px; }
</style>
<nav class="nav">
  <strong>AutoPentestX</strong>
  <a href="/">Scans</a>
  <a href="/attack-graph/{{ scan_id }}">Attack Graph</a>
  <a href="/c2">C2 Sessions</a>
</nav>
<div class="container">
  <h1>Scan #{{ scan_id }} — Findings</h1>

  <div class="grid" style="margin-bottom:24px">
    {% set critical = (vulns + web_vulns)|selectattr('risk_level','equalto','CRITICAL')|list|length %}
    {% set high     = (vulns + web_vulns)|selectattr('risk_level','equalto','HIGH')|list|length %}
    <div class="card"><div style="color:var(--muted);font-size:12px">PORTS</div>
      <div class="stat">{{ ports|length }}</div></div>
    <div class="card"><div style="color:var(--muted);font-size:12px">TOTAL VULNS</div>
      <div class="stat">{{ vulns|length + web_vulns|length }}</div></div>
    <div class="card"><div style="color:var(--muted);font-size:12px">CRITICAL</div>
      <div class="stat" style="color:var(--danger)">{{ critical }}</div></div>
    <div class="card"><div style="color:var(--muted);font-size:12px">HIGH</div>
      <div class="stat" style="color:#e67e22">{{ high }}</div></div>
  </div>

  <h2>Network Vulnerabilities</h2>
  <input id="filter" placeholder="Filter by name, CVE, service…" oninput="filterTable(this,'nvt')">
  <table id="nvt">
    <tr><th>Port</th><th>Service</th><th>CVE</th><th>Name</th><th>CVSS</th><th>Risk</th></tr>
    {% for v in vulns %}
    <tr>
      <td>{{ v.port or '—' }}</td>
      <td>{{ v.service or '—' }}</td>
      <td>{{ v.cve_id or '—' }}</td>
      <td>{{ v.name or v.description[:80] if v.description else '—' }}</td>
      <td>{{ '%.1f'|format(v.cvss_score) if v.cvss_score else '—' }}</td>
      <td><span class="badge {{ v.risk_level or 'UNKNOWN' }}">{{ v.risk_level or 'UNKNOWN' }}</span></td>
    </tr>
    {% else %}
    <tr><td colspan="6" style="color:var(--muted);text-align:center">None</td></tr>
    {% endfor %}
  </table>

  <h2>Web Vulnerabilities</h2>
  <input id="filter2" placeholder="Filter by type, URL, parameter…" oninput="filterTable(this,'wvt')">
  <table id="wvt">
    <tr><th>Type</th><th>URL</th><th>Parameter</th><th>Severity</th><th>Confidence</th></tr>
    {% for v in web_vulns %}
    <tr>
      <td><strong>{{ v.vuln_type or v.name or '—' }}</strong></td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis">
        {{ v.url or v.endpoint or '—' }}</td>
      <td>{{ v.parameter or v.param or '—' }}</td>
      <td><span class="badge {{ v.risk_level or v.severity or 'UNKNOWN' }}">
        {{ v.risk_level or v.severity or 'UNKNOWN' }}</span></td>
      <td>{{ '%.0f%%'|format(v.confidence*100) if v.confidence else '—' }}</td>
    </tr>
    {% else %}
    <tr><td colspan="5" style="color:var(--muted);text-align:center">None</td></tr>
    {% endfor %}
  </table>
</div>
<script>
function filterTable(inp, tableId) {
  const q = inp.value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tr:not(:first-child)').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
"""

_GRAPH_HTML = """<!doctype html>
<title>Attack Graph — Scan {{ scan_id }}</title>
<style>""" + _BASE_CSS + """
body { overflow: hidden; }
#graph-container { width: 100vw; height: calc(100vh - 52px); }
.legend { position:fixed; bottom:16px; left:16px; background:var(--surface);
          border:1px solid var(--border); border-radius:8px; padding:12px; font-size:12px; }
.legend-item { display:flex; align-items:center; gap:8px; margin-bottom:4px; }
.legend-dot { width:12px; height:12px; border-radius:50%; flex-shrink:0; }
#tooltip { position:fixed; background:var(--surface); border:1px solid var(--border);
           border-radius:6px; padding:10px 14px; font-size:12px; pointer-events:none;
           opacity:0; transition:opacity .15s; max-width:280px; }
</style>
<nav class="nav">
  <strong>AutoPentestX</strong>
  <a href="/">Scans</a>
  <a href="/scan/{{ scan_id }}">Findings</a>
  <a href="/c2">C2</a>
  <span style="margin-left:auto;color:var(--muted)">Attack Path Graph — Scan #{{ scan_id }}</span>
</nav>
<div id="graph-container"></div>
<div id="tooltip"></div>
<div class="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#2c3e50"></div>Target</div>
  <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div>CRITICAL</div>
  <div class="legend-item"><div class="legend-dot" style="background:#e67e22"></div>HIGH</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f1c40f"></div>MEDIUM</div>
  <div class="legend-item"><div class="legend-dot" style="background:#27ae60"></div>LOW</div>
  <div class="legend-item"><div class="legend-dot" style="background:#c0392b"></div>Impact</div>
</div>
<script>
const SCAN_ID = {{ scan_id }};
const tip = document.getElementById('tooltip');

fetch('/api/scan/' + SCAN_ID + '/graph')
  .then(r => r.json())
  .then(data => renderGraph(data));

function renderGraph(data) {
  const W = window.innerWidth, H = window.innerHeight - 52;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', W); svg.setAttribute('height', H);
  svg.style.display = 'block';

  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
  marker.setAttribute('id', 'arrow');
  marker.setAttribute('markerWidth', '8'); marker.setAttribute('markerHeight', '8');
  marker.setAttribute('refX', '6'); marker.setAttribute('refY', '3');
  marker.setAttribute('orient', 'auto');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M0,0 L0,6 L8,3 z');
  path.setAttribute('fill', '#58a6ff44');
  marker.appendChild(path); defs.appendChild(marker); svg.appendChild(defs);

  const nodes = data.nodes, links = data.links;
  if (!nodes.length) {
    const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', W/2); t.setAttribute('y', H/2);
    t.setAttribute('fill','#8b949e'); t.setAttribute('text-anchor','middle');
    t.textContent = 'No findings for scan #' + SCAN_ID;
    svg.appendChild(t);
    document.getElementById('graph-container').appendChild(svg);
    return;
  }

  const pos = nodes.map((n, i) => ({
    x: W/2 + (Math.random()-.5)*400,
    y: H/2 + (Math.random()-.5)*300,
    vx: 0, vy: 0, n
  }));

  const nodeMap = {};
  nodes.forEach((n, i) => nodeMap[n.id] = i);

  function simulate(steps) {
    for (let s = 0; s < steps; s++) {
      for (let i = 0; i < pos.length; i++)
        for (let j = i+1; j < pos.length; j++) {
          const dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y;
          const d = Math.sqrt(dx*dx+dy*dy) || 1;
          const f = 4000 / (d*d);
          pos[i].vx += dx/d*f; pos[i].vy += dy/d*f;
          pos[j].vx -= dx/d*f; pos[j].vy -= dy/d*f;
        }
      for (const lk of links) {
        const si = nodeMap[lk.source], ti = nodeMap[lk.target];
        if (si === undefined || ti === undefined) continue;
        const dx = pos[ti].x - pos[si].x, dy = pos[ti].y - pos[si].y;
        const d = Math.sqrt(dx*dx+dy*dy) || 1;
        const f = (d - 150) * 0.05;
        pos[si].vx += dx/d*f; pos[si].vy += dy/d*f;
        pos[ti].vx -= dx/d*f; pos[ti].vy -= dy/d*f;
      }
      for (const p of pos) {
        p.vx += (W/2 - p.x) * 0.002;
        p.vy += (H/2 - p.y) * 0.002;
        p.x += p.vx * 0.5; p.y += p.vy * 0.5;
        p.vx *= 0.7; p.vy *= 0.7;
        p.x = Math.max(60, Math.min(W-60, p.x));
        p.y = Math.max(30, Math.min(H-30, p.y));
      }
    }
  }
  simulate(200);

  for (const lk of links) {
    const si = nodeMap[lk.source], ti = nodeMap[lk.target];
    if (si === undefined || ti === undefined) continue;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', pos[si].x); line.setAttribute('y1', pos[si].y);
    line.setAttribute('x2', pos[ti].x); line.setAttribute('y2', pos[ti].y);
    line.setAttribute('stroke', '#58a6ff33');
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('marker-end', 'url(#arrow)');
    svg.appendChild(line);
    if (lk.label) {
      const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      lbl.setAttribute('x', (pos[si].x+pos[ti].x)/2);
      lbl.setAttribute('y', (pos[si].y+pos[ti].y)/2 - 4);
      lbl.setAttribute('fill', '#8b949e'); lbl.setAttribute('font-size', '10');
      lbl.setAttribute('text-anchor', 'middle');
      lbl.textContent = lk.label;
      svg.appendChild(lbl);
    }
  }

  for (let i = 0; i < pos.length; i++) {
    const p = pos[i], n = p.n;
    const r = n.type === 'target' ? 22 : n.type === 'impact' ? 14 : 18;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('cursor', 'pointer');
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', p.x); circle.setAttribute('cy', p.y);
    circle.setAttribute('r', r);
    circle.setAttribute('fill', n.color + (n.type === 'impact' ? '66' : 'cc'));
    circle.setAttribute('stroke', n.color);
    circle.setAttribute('stroke-width', '2');
    g.appendChild(circle);
    const lines = n.label.split('\\n');
    lines.forEach((line, li) => {
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      t.setAttribute('x', p.x);
      t.setAttribute('y', p.y + r + 14 + li*13);
      t.setAttribute('fill', '#c9d1d9'); t.setAttribute('font-size', '11');
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('font-family', 'monospace');
      t.textContent = line.length > 22 ? line.slice(0,20)+'..' : line;
      g.appendChild(t);
    });
    g.addEventListener('mouseover', (e) => {
      tip.style.opacity = '1';
      tip.innerHTML = '<strong>' + n.label.replace('\\n',' ') + '</strong>' +
        (n.severity ? '<br>Severity: ' + n.severity : '') +
        (n.cvss ? '<br>CVSS: ' + n.cvss.toFixed(1) : '') +
        (n.url ? '<br>URL: ' + n.url.slice(0,60) : '') +
        '<br>Type: ' + n.type;
    });
    g.addEventListener('mousemove', (e) => {
      tip.style.left = (e.clientX+16)+'px';
      tip.style.top  = (e.clientY+16)+'px';
    });
    g.addEventListener('mouseleave', () => { tip.style.opacity='0'; });
    svg.appendChild(g);
  }
  document.getElementById('graph-container').appendChild(svg);
}
</script>
"""

_C2_HTML = """<!doctype html>
<title>C2 Sessions — AutoPentestX</title>
<style>""" + _BASE_CSS + """
.online  { color:#27ae60; }
.stale   { color:#e67e22; }
.offline { color:#e74c3c; }
</style>
<nav class="nav">
  <strong>AutoPentestX</strong>
  <a href="/">Scans</a>
  <a href="/c2">C2 Sessions</a>
</nav>
<div class="container">
  <h1>C2 Sessions</h1>
  {% if not sessions %}
  <div class="card" style="color:var(--muted);text-align:center;padding:40px">
    No active C2 sessions. Start with: python modules/c2_server.py
  </div>
  {% else %}
  <table>
    <tr>
      <th>Session ID</th><th>Host</th><th>User</th><th>OS/Arch</th>
      <th>Ext IP</th><th>PID</th><th>Last Seen</th><th>Sleep</th>
    </tr>
    {% for s in sessions %}
    {% set age = (now - s.last_seen_at) if s.last_seen_at else 9999 %}
    <tr>
      <td style="font-family:monospace;font-size:12px">{{ s.id[:12] }}…</td>
      <td><strong>{{ s.host or '?' }}</strong></td>
      <td>{{ s.user or '?' }}</td>
      <td>{{ s.os or '?' }}/{{ s.arch or '?' }}</td>
      <td>{{ s.external_ip or '?' }}</td>
      <td>{{ s.pid or '?' }}</td>
      <td class="{{ 'online' if age < 30 else 'stale' if age < 120 else 'offline' }}">
        {{ age }}s ago
      </td>
      <td>{{ s.sleep_seconds }}s</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
"""


def _write_templates() -> None:
    """Write Jinja2 templates to the templates/ directory."""
    tdir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(tdir, exist_ok=True)

    def _w(name, content):
        path = os.path.join(tdir, name)
        if not os.path.exists(path) or open(path).read() != content:
            with open(path, 'w') as f:
                f.write(content)

    _w('index.html', _INDEX_HTML)
    _w('scan.html',  _SCAN_HTML)
    _w('graph.html', _GRAPH_HTML)
    _w('c2.html',    _C2_HTML)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    global DB_PATH
    ap = argparse.ArgumentParser(description='AutoPentestX Dashboard')
    ap.add_argument('--host',  default='127.0.0.1')
    ap.add_argument('--port',  type=int, default=5000)
    ap.add_argument('--db',    default=DB_PATH)
    ap.add_argument('--debug', action='store_true')
    args = ap.parse_args()
    DB_PATH = args.db

    if not HAS_FLASK:
        print('[!] Flask not installed.  Install with: pip install flask')
        sys.exit(1)

    _write_templates()

    import time as _time

    @app.context_processor
    def inject_globals():
        return {'now': int(_time.time())}

    print(f'[+] AutoPentestX Dashboard → http://{args.host}:{args.port}')
    print(f'[+] Database: {DB_PATH}')
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == '__main__':
    main()
