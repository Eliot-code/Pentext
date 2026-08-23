"""Unit tests for modules/heuristic_engine.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from modules.heuristic_engine import (
    AnomalyScorer,
    BayesianFusion,
    HeuristicEngine,
    _grade,
    correlate,
    deduplicate,
)


class TestBayesianFusion:

    def test_bayesian_fusion_increases_with_evidence(self):
        fusion = BayesianFusion('SQL Injection')
        prior = fusion.posterior
        fusion.update(5.0, weight=1.0)
        assert fusion.posterior > prior

    def test_bayesian_fusion_decreases_with_counter_evidence(self):
        fusion = BayesianFusion('SQL Injection')
        prior = fusion.posterior
        fusion.update(0.1, weight=1.0)
        assert fusion.posterior < prior

    def test_bayesian_fusion_kev_bonus(self):
        fusion = BayesianFusion('SQL Injection')
        fusion.update(BayesianFusion.evidence_to_lr(0.92), weight=1.0)
        fusion.update(5.0, weight=0.9)
        assert fusion.posterior >= 0.70, (
            f'Expected posterior >= 0.70 for KEV+confirmed entry, got {fusion.posterior}')

    def test_zero_lr_is_ignored(self):
        fusion = BayesianFusion('Reflected XSS')
        before = fusion.posterior
        fusion.update(0, weight=1.0)
        assert fusion.posterior == before

    def test_evidence_to_lr_high_confidence(self):
        lr = BayesianFusion.evidence_to_lr(0.9)
        assert lr > 1.0

    def test_evidence_to_lr_low_confidence(self):
        lr = BayesianFusion.evidence_to_lr(0.1)
        assert lr < 1.0


class TestAnomalyScorer:

    def _build_baseline(self):
        baseline = []
        for _ in range(30):
            baseline.append([2.0, 0.05, 0.20, 0.25, 0.3])
        return baseline

    def test_anomaly_scorer_trains_and_scores(self):
        scorer = AnomalyScorer()
        import random
        rng = random.Random(1)
        baseline = [[2.0 + rng.gauss(0, 0.05),
                     0.05 + rng.gauss(0, 0.01),
                     0.2  + rng.gauss(0, 0.02),
                     0.3  + rng.gauss(0, 0.05),
                     0.3  + rng.gauss(0, 0.03)]
                    for _ in range(60)]
        scorer.fit(baseline)
        normal_point = [2.0, 0.05, 0.2, 0.3, 0.3]
        ood_point = [5.0, 10.0, 9.9, 1.0, 0.0]
        score_normal = scorer.score(normal_point)
        score_ood    = scorer.score(ood_point)
        assert score_ood > score_normal, (
            f'OOD score {score_ood:.3f} should exceed normal score {score_normal:.3f}')

    def test_untrained_scorer_returns_half(self):
        scorer = AnomalyScorer()
        assert scorer.score([1.0, 2.0, 3.0]) == 0.5

    def test_fit_requires_at_least_4_vectors(self):
        scorer = AnomalyScorer()
        scorer.fit([[1.0], [2.0], [3.0]])
        assert scorer.score([1.0]) == 0.5


class TestDeduplicate:

    def _finding(self, vuln_type, url, param, confidence):
        return {'vuln_type': vuln_type, 'url': url, 'parameter': param, 'confidence': confidence}

    def test_deduplication_merges_same_url_and_param(self):
        findings = [
            self._finding('SQL Injection', 'http://t.com/search', 'q', 0.6),
            self._finding('SQL Injection', 'http://t.com/search', 'q', 0.5),
        ]
        result = deduplicate(findings)
        assert len(result) == 1

    def test_deduplication_keeps_highest_confidence(self):
        findings = [
            self._finding('SQL Injection', 'http://t.com/login', 'user', 0.4),
            self._finding('SQL Injection', 'http://t.com/login', 'user', 0.9),
            self._finding('SQL Injection', 'http://t.com/login', 'user', 0.7),
        ]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0]['confidence'] == 0.9

    def test_deduplication_keeps_different_params(self):
        findings = [
            self._finding('SQL Injection', 'http://t.com/q', 'a', 0.8),
            self._finding('SQL Injection', 'http://t.com/q', 'b', 0.8),
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_deduplication_empty_list(self):
        assert deduplicate([]) == []


class TestCorrelate:

    def test_correlate_adds_chains(self):
        findings = [{'vuln_type': 'SQL Injection', 'confidence': 0.8}]
        result = correlate(findings)
        assert 'Remote Code Execution' in result[0].get('chains', [])

    def test_correlate_unknown_type_has_no_chains(self):
        findings = [{'vuln_type': 'Unknown Thing', 'confidence': 0.5}]
        result = correlate(findings)
        assert result[0].get('chains', []) == []

    def test_correlate_preserves_existing_keys(self):
        findings = [{'vuln_type': 'SSRF', 'confidence': 0.9, 'extra': 'foo'}]
        result = correlate(findings)
        assert result[0].get('extra') == 'foo'


class TestHeuristicEnginePipeline:

    def _make_findings(self):
        return [
            {'vuln_type': 'SQL Injection', 'url': 'http://target.local/search?q=1',
             'parameter': 'q', 'confidence': 0.85, 'verified': True,
             'status_code': 200, 'response_length': 1500, 'response_time_ms': 300},
            {'vuln_type': 'Reflected XSS', 'url': 'http://target.local/page',
             'parameter': 'name', 'confidence': 0.70},
            {'vuln_type': 'SSRF', 'url': 'http://target.local/proxy',
             'parameter': 'url', 'confidence': 0.50},
            {'vuln_type': 'Open Redirect', 'url': 'http://target.local/redir',
             'parameter': 'next', 'confidence': 0.40},
            {'vuln_type': 'Path Traversal', 'url': 'http://target.local/file',
             'parameter': 'path', 'confidence': 0.30},
        ]

    def test_heuristic_engine_full_pipeline(self):
        engine = HeuristicEngine()
        findings = self._make_findings()
        results = engine.analyze(findings)
        assert len(results) == 5
        top = results[0]
        assert top.grade in ('CONFIRMED', 'PROBABLE')
        assert top.fused_confidence > 0
        confidences = [r.fused_confidence for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_heuristic_engine_deduplication_in_pipeline(self):
        engine = HeuristicEngine()
        dup = {'vuln_type': 'Command Injection', 'url': 'http://t.com/cmd',
               'parameter': 'arg', 'confidence': 0.8}
        results = engine.analyze([dup, dict(dup)])
        assert len(results) == 1

    def test_heuristic_engine_empty_input(self):
        engine = HeuristicEngine()
        assert engine.analyze([]) == []

    def test_heuristic_engine_grades_are_valid(self):
        engine = HeuristicEngine()
        results = engine.analyze(self._make_findings())
        valid_grades = {'CONFIRMED', 'PROBABLE', 'SUSPECTED', 'NOISE'}
        for r in results:
            assert r.grade in valid_grades, f'Unexpected grade: {r.grade}'

    def test_grade_function(self):
        assert _grade(0.95) == 'CONFIRMED'
        assert _grade(0.90) == 'CONFIRMED'
        assert _grade(0.80) == 'PROBABLE'
        assert _grade(0.70) == 'PROBABLE'
        assert _grade(0.60) == 'SUSPECTED'
        assert _grade(0.45) == 'SUSPECTED'
        assert _grade(0.44) == 'NOISE'
        assert _grade(0.00) == 'NOISE'
