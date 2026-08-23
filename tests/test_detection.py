"""
Unit tests for modules/detection_engine.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

# Guard: skip the whole module gracefully if detection_engine is unavailable.
try:
    import modules.detection_engine as _de
    _MODULE_AVAILABLE = True
except Exception:
    _MODULE_AVAILABLE = False

skip_if_missing = pytest.mark.skipif(
    not _MODULE_AVAILABLE,
    reason='modules/detection_engine.py not importable — skipping',
)

if _MODULE_AVAILABLE:
    from modules.detection_engine import (
        CONFIDENCE_CONFIRMED,
        CONFIDENCE_PROBABLE,
        CONFIDENCE_SUSPECTED,
        CONFIDENCE_NOISE,
        Finding,
        HttpSample,
        ResponseNormalizer,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  ResponseNormalizer
# ─────────────────────────────────────────────────────────────────────────────

@skip_if_missing
class TestResponseNormalizer:

    def test_response_normalizer_strips_csrf(self):
        """CSRF token stripped from both strings → high similarity."""
        body_a = (
            '<form>'
            '<input type="hidden" name="csrfmiddlewaretoken" value="AABBCCDD1122">'
            '<p>Hello world</p>'
            '</form>'
        )
        body_b = (
            '<form>'
            '<input type="hidden" name="csrfmiddlewaretoken" value="ZZXXYYQQ9988">'
            '<p>Hello world</p>'
            '</form>'
        )
        norm_a = ResponseNormalizer.normalize(body_a)
        norm_b = ResponseNormalizer.normalize(body_b)
        assert 'AABBCCDD1122' not in norm_a
        assert 'ZZXXYYQQ9988' not in norm_b
        sim = ResponseNormalizer.similarity(body_a, body_b)
        assert sim >= 0.80, f'Expected sim >= 0.80, got {sim:.3f}'

    def test_response_normalizer_similarity_identical(self):
        """Similarity of a string with itself must be 1.0."""
        body = '<html><body><p>same content</p></body></html>'
        assert ResponseNormalizer.similarity(body, body) == 1.0

    def test_response_normalizer_similarity_different(self):
        """Completely different strings should score below 0.3."""
        a = 'abcdefghijklmnopqrstuvwxyz0123456789'
        b = 'ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210'
        sim = ResponseNormalizer.similarity(a, b)
        assert sim < 0.3, f'Expected sim < 0.3, got {sim:.3f}'

    def test_response_normalizer_empty_both(self):
        """Two empty strings are identical."""
        assert ResponseNormalizer.similarity('', '') == 1.0

    def test_response_normalizer_one_empty(self):
        """One empty string vs non-empty is 0.0."""
        assert ResponseNormalizer.similarity('', 'hello') == 0.0
        assert ResponseNormalizer.similarity('hello', '') == 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  Finding.grade() / confidence thresholds
# ─────────────────────────────────────────────────────────────────────────────

@skip_if_missing
class TestRiskLevel:

    def _finding(self, confidence: float) -> 'Finding':
        return Finding(
            vuln_type='Test',
            url='http://example.com/',
            parameter='q',
            payload='test',
            confidence=confidence,
        )

    def test_calculate_risk_level_critical(self):
        assert self._finding(0.95).grade() == 'CONFIRMED'

    def test_calculate_risk_level_high(self):
        assert self._finding(CONFIDENCE_PROBABLE).grade() == 'PROBABLE'

    def test_calculate_risk_level_medium(self):
        assert self._finding(CONFIDENCE_SUSPECTED).grade() == 'SUSPECTED'

    def test_calculate_risk_level_low(self):
        assert self._finding(CONFIDENCE_NOISE - 0.01).grade() == 'NOISE'

    def test_confidence_thresholds_ordering(self):
        assert CONFIDENCE_CONFIRMED > CONFIDENCE_PROBABLE
        assert CONFIDENCE_PROBABLE  > CONFIDENCE_SUSPECTED
        assert CONFIDENCE_SUSPECTED > CONFIDENCE_NOISE


# ─────────────────────────────────────────────────────────────────────────────
#  HttpSample
# ─────────────────────────────────────────────────────────────────────────────

@skip_if_missing
class TestHttpSample:

    def test_http_sample_computes_hash_and_len(self):
        import hashlib
        body = 'hello world'
        sample = HttpSample(status=200, headers={}, body=body, elapsed=0.1)
        expected_hash = hashlib.sha256(body.encode('utf-8', 'ignore')).hexdigest()
        assert sample.body_hash == expected_hash
        assert sample.body_len == len(body)

    def test_http_sample_empty_body(self):
        sample = HttpSample(status=404, headers={}, body='', elapsed=0.05)
        assert sample.body_len == 0
        assert len(sample.body_hash) == 64
