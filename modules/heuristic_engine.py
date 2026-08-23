#!/usr/bin/env python3
"""AutoPentestX - Heuristic & Bayesian Fusion Engine"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


VULN_CHAIN_GRAPH: Dict[str, List[str]] = {
    'SQL Injection':          ['Remote Code Execution', 'Authentication Bypass', 'Data Exfiltration'],
    'Command Injection':      ['Remote Code Execution', 'Lateral Movement'],
    'SSRF':                   ['Internal Network Access', 'Cloud Metadata Exposure'],
    'Path Traversal':         ['Sensitive File Disclosure', 'Authentication Bypass'],
    'File Upload':            ['Remote Code Execution', 'Stored XSS'],
    'Stored XSS':             ['Session Hijacking', 'Credential Harvesting'],
    'Reflected XSS':          ['Session Hijacking'],
    'XXE':                    ['SSRF', 'Sensitive File Disclosure'],
    'Deserialization':        ['Remote Code Execution'],
    'SSTI':                   ['Remote Code Execution'],
}

_BASE_RATES: Dict[str, float] = {
    'SQL Injection':          0.06,
    'Reflected XSS':          0.12,
    'Stored XSS':             0.04,
    'Command Injection':      0.03,
    'SSRF':                   0.05,
    'Path Traversal':         0.08,
    'File Upload':            0.04,
    'SSTI':                   0.02,
    'XXE':                    0.03,
    'Open Redirect':          0.09,
    'Deserialization':        0.02,
    'Remote Code Execution':  0.01,
    '_default':               0.05,
}


def _base_rate(vuln_type: str) -> float:
    return _BASE_RATES.get(vuln_type, _BASE_RATES['_default'])


class BayesianFusion:
    def __init__(self, vuln_type: str) -> None:
        self.prior = _base_rate(vuln_type)
        self._log_odds = math.log(self.prior / (1 - self.prior))

    def update(self, likelihood_ratio: float, weight: float = 1.0) -> 'BayesianFusion':
        if likelihood_ratio <= 0:
            return self
        effective_lr = likelihood_ratio ** max(0.0, min(1.0, weight))
        self._log_odds += math.log(effective_lr)
        return self

    @property
    def posterior(self) -> float:
        lo = max(-30.0, min(30.0, self._log_odds))
        p = math.exp(lo) / (1 + math.exp(lo))
        return round(p, 4)

    @staticmethod
    def evidence_to_lr(raw_confidence: float) -> float:
        c = max(1e-6, min(1 - 1e-6, raw_confidence))
        return c / (1 - c)


def _c_factor(n: int) -> float:
    if n <= 1:
        return 0.0
    h = math.log(n - 1) + 0.5772156649
    return 2 * h - 2 * (n - 1) / n


class _IsolationTree:
    def __init__(self, data: List[List[float]], height_limit: int, rng: random.Random) -> None:
        self._root = self._build(data, 0, height_limit, rng)

    @staticmethod
    def _build(data, depth, limit, rng):
        if depth >= limit or len(data) <= 1:
            return {'type': 'leaf', 'size': len(data)}
        n_features = len(data[0])
        feat = rng.randint(0, n_features - 1)
        vals = [row[feat] for row in data]
        mn, mx = min(vals), max(vals)
        if mn == mx:
            return {'type': 'leaf', 'size': len(data)}
        split = rng.uniform(mn, mx)
        left  = [row for row in data if row[feat] < split]
        right = [row for row in data if row[feat] >= split]
        return {'type': 'node', 'feat': feat, 'split': split,
                'left': _IsolationTree._build(left, depth + 1, limit, rng),
                'right': _IsolationTree._build(right, depth + 1, limit, rng)}

    def path_length(self, x: List[float]) -> float:
        return self._pl(self._root, x, 0)

    def _pl(self, node, x, depth) -> float:
        if node['type'] == 'leaf':
            return depth + _c_factor(node['size'])
        if x[node['feat']] < node['split']:
            return self._pl(node['left'],  x, depth + 1)
        return self._pl(node['right'], x, depth + 1)


class AnomalyScorer:
    N_TREES   = 40
    SUBSAMPLE = 64

    def __init__(self) -> None:
        self._trees: List[_IsolationTree] = []
        self._trained = False
        self._rng = random.Random(42)

    def fit(self, vectors: List[List[float]]) -> None:
        if len(vectors) < 4:
            return
        limit = math.ceil(math.log2(min(self.SUBSAMPLE, len(vectors))))
        self._trees = []
        for _ in range(self.N_TREES):
            sample = self._rng.choices(vectors, k=min(self.SUBSAMPLE, len(vectors)))
            self._trees.append(_IsolationTree(sample, limit, self._rng))
        self._trained = True
        self._c = _c_factor(min(self.SUBSAMPLE, len(vectors)))

    def score(self, vector: List[float]) -> float:
        if not self._trained or not self._trees:
            return 0.5
        avg_path = statistics.mean(t.path_length(vector) for t in self._trees)
        if self._c == 0:
            return 0.5
        return 2 ** (-avg_path / self._c)


def _finding_key(f: Dict[str, Any]) -> str:
    vuln  = (f.get('vuln_type') or f.get('type') or 'unknown').lower()
    url   = f.get('url') or f.get('endpoint') or ''
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path
    except Exception:
        path = url
    param = (f.get('parameter') or f.get('param') or '').lower()
    raw = f'{vuln}|{path}|{param}'
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        k = _finding_key(f)
        if k not in seen:
            seen[k] = dict(f)
        else:
            c_new = f.get('confidence', 0)
            c_old = seen[k].get('confidence', 0)
            if c_new > c_old:
                seen[k] = dict(f)
    return list(seen.values())


def correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for f in findings:
        vuln = f.get('vuln_type') or f.get('type') or ''
        chains = VULN_CHAIN_GRAPH.get(vuln, [])
        if chains:
            f['chains'] = chains
    return findings


@dataclass
class HeuristicResult:
    finding:          Dict[str, Any]
    fused_confidence: float
    anomaly_score:    float
    grade:            str
    chains:           List[str] = field(default_factory=list)
    notes:            List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {**self.finding, 'fused_confidence': self.fused_confidence,
                'anomaly_score': self.anomaly_score, 'grade': self.grade,
                'chains': self.chains, 'notes': self.notes}


_GRADE_THRESHOLDS = (
    (0.90, 'CONFIRMED'),
    (0.70, 'PROBABLE'),
    (0.45, 'SUSPECTED'),
    (0.00, 'NOISE'),
)


def _grade(p: float) -> str:
    for threshold, label in _GRADE_THRESHOLDS:
        if p >= threshold:
            return label
    return 'NOISE'


class HeuristicEngine:
    def __init__(self) -> None:
        self._anomaly = AnomalyScorer()

    def train_baseline(self, vectors: List[List[float]]) -> None:
        self._anomaly.fit(vectors)

    def _response_vector(self, f: Dict[str, Any]) -> List[float]:
        return [
            float(f.get('status_code', 200)) / 100.0,
            float(f.get('response_length', 1000)) / 10000.0,
            float(f.get('response_time_ms', 200)) / 1000.0,
            float(f.get('confidence', 0.5)),
            float(len(f.get('vuln_type', ''))) / 30.0,
        ]

    def analyze(self, raw_findings: List[Dict[str, Any]],
                ti_results: Optional[Dict[str, Any]] = None) -> List[HeuristicResult]:
        if not raw_findings:
            return []
        unique = deduplicate(raw_findings)
        results: List[HeuristicResult] = []
        for f in unique:
            vuln_type = f.get('vuln_type') or f.get('type') or 'unknown'
            raw_conf  = float(f.get('confidence', 0.5))
            fusion = BayesianFusion(vuln_type)
            fusion.update(BayesianFusion.evidence_to_lr(raw_conf), weight=1.0)
            if ti_results:
                cve_id = f.get('cve_id', '')
                ti = ti_results.get(cve_id, {})
                if ti.get('in_kev'):
                    fusion.update(5.0, weight=0.9)
                if ti.get('exploit_available'):
                    fusion.update(3.0, weight=0.8)
                epss = float(ti.get('epss_probability', 0))
                if epss > 0:
                    fusion.update(BayesianFusion.evidence_to_lr(epss), weight=0.6)
            if f.get('verified', False):
                fusion.update(8.0, weight=1.0)
            elif f.get('payload_reflected', False):
                fusion.update(2.0, weight=0.7)
            if f.get('honeypot', False):
                fusion.update(0.1, weight=0.9)
            posterior = fusion.posterior
            anomaly   = self._anomaly.score(self._response_vector(f))
            grade     = _grade(posterior)
            chains    = VULN_CHAIN_GRAPH.get(vuln_type, [])
            notes: List[str] = []
            if anomaly > 0.65:
                notes.append(f'anomaly_score={anomaly:.2f} (statistically unusual)')
            if f.get('in_kev') or (ti_results and ti_results.get(f.get('cve_id', ''), {}).get('in_kev')):
                notes.append('CISA KEV: actively exploited in the wild')
            results.append(HeuristicResult(
                finding=f, fused_confidence=posterior, anomaly_score=anomaly,
                grade=grade, chains=chains, notes=notes))
        for r in results:
            r.finding['chains'] = r.chains
        results.sort(key=lambda r: r.fused_confidence * (1 + 0.3 * r.anomaly_score), reverse=True)
        return results

    def print_summary(self, results: List[HeuristicResult]) -> None:
        print('\n' + '=' * 70)
        print('HEURISTIC ENGINE — FUSED FINDINGS')
        print('=' * 70)
        grade_counts: Dict[str, int] = defaultdict(int)
        for r in results:
            grade_counts[r.grade] += 1
        for label in ('CONFIRMED', 'PROBABLE', 'SUSPECTED', 'NOISE'):
            print(f'  {label:12s}: {grade_counts[label]}')
        print('=' * 70)
        for r in results:
            if r.grade == 'NOISE':
                continue
            f = r.finding
            print(f'\n  [{r.grade}] {f.get("vuln_type", f.get("type", "?"))}')
            if url := f.get('url') or f.get('endpoint'):
                print(f'    URL      : {url}')
            if param := f.get('parameter') or f.get('param'):
                print(f'    Param    : {param}')
            print(f'    Confidence: {r.fused_confidence:.3f}  Anomaly: {r.anomaly_score:.3f}')
            if r.chains:
                print(f'    Chains   : {", ".join(r.chains)}')
            for note in r.notes:
                print(f'    Note     : {note}')
        print('\n' + '=' * 70 + '\n')

    def get_results(self, raw_findings: List[Dict[str, Any]],
                    ti_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = self.analyze(raw_findings, ti_results)
        return [r.as_dict() for r in results]
