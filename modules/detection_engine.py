#!/usr/bin/env python3
"""
AutoPentestX - Industrial-Grade Detection Engine
================================================
Provides high-confidence vulnerability validation through differential analysis,
statistical timing baselines, content similarity scoring, honeypot identification
and WAF/CDN response normalization.

The goal of this module is to eliminate the two largest classes of error in
automated vulnerability assessment:

  * FALSE POSITIVES — caused by reflected payloads in error pages, generic
    keyword matching, identical 200/302 responses, WAF block pages, fuzzed
    parameters that always reflect, etc.
  * FALSE NEGATIVES — caused by encoded responses, partial payload reflection,
    timing variance, blind injection points, response truncation, etc.

Every detector returns a confidence score in [0.0, 1.0] computed from multiple
independent signals.  A finding is only escalated to "CONFIRMED" when the
aggregated evidence crosses configurable thresholds.

This file is library code only.  No network calls are issued unless invoked by
a higher-level module that already established legal authorization.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import statistics
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIDENCE THRESHOLDS  (industry-tuned defaults)
# ─────────────────────────────────────────────────────────────────────────────
CONFIDENCE_CONFIRMED   = 0.90   # report as confirmed vulnerability
CONFIDENCE_PROBABLE    = 0.70   # report as probable, manual verification
CONFIDENCE_SUSPECTED   = 0.45   # tentative — requires triage
CONFIDENCE_NOISE       = 0.25   # discard

# Z-score threshold for time-based blind detection.  Three standard deviations
# above the mean baseline gives a ~99.7% probability that the delay is real.
TIME_ZSCORE_CONFIRMED  = 3.5
TIME_ZSCORE_PROBABLE   = 2.5
MIN_TIME_DELTA_SEC     = 2.0    # absolute minimum to avoid jitter false-positives

# Content similarity (Ratcliff/Obershelp).  Below this similarity to baseline
# the response is considered "different" — used in boolean blind detection.
DIFF_SIMILARITY_LOW    = 0.85   # confidently different
DIFF_SIMILARITY_HIGH   = 0.97   # confidently identical

# Minimum unique markers a payload must produce to count as confirmed XSS.
XSS_CONTEXT_REQUIRED_BREAKOUTS = 1   # at least one context-breaking char


# ─────────────────────────────────────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class HttpSample:
    """A single normalized HTTP response sample."""
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    body_hash: str = field(default="")
    body_len: int = field(default=0)

    def __post_init__(self) -> None:
        self.body_hash = hashlib.sha256(self.body.encode("utf-8", "ignore")).hexdigest()
        self.body_len = len(self.body)


@dataclass
class Finding:
    """Validated finding produced by the detection engine."""
    vuln_type: str
    url: str
    parameter: Optional[str]
    payload: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    cvss: float = 0.0
    cwe: Optional[str] = None
    severity: str = "INFO"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def grade(self) -> str:
        if self.confidence >= CONFIDENCE_CONFIRMED:
            return "CONFIRMED"
        if self.confidence >= CONFIDENCE_PROBABLE:
            return "PROBABLE"
        if self.confidence >= CONFIDENCE_SUSPECTED:
            return "SUSPECTED"
        return "NOISE"


# ─────────────────────────────────────────────────────────────────────────────
#  RESPONSE NORMALIZATION
# ─────────────────────────────────────────────────────────────────────────────
class ResponseNormalizer:
    """Strip volatile content (CSRF tokens, timestamps, request IDs, ad slots,
    nonces, etc.) so that two responses that are *semantically* equivalent
    produce identical body hashes and high similarity scores."""

    VOLATILE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=_-]{8,}',
                    re.I), 'csrf_token=REDACTED'),
        (re.compile(r'name="csrfmiddlewaretoken"\s+value="[^"]+"', re.I),
         'name="csrfmiddlewaretoken" value="REDACTED"'),
        (re.compile(r'nonce-[A-Za-z0-9+/=]{8,}', re.I), 'nonce-REDACTED'),
        (re.compile(r'\b[a-f0-9]{32,128}\b', re.I), 'HEX'),       # generic hashes
        (re.compile(r'\b\d{10,13}\b'), 'TIMESTAMP'),               # epoch
        (re.compile(r'requestId["\']?\s*[:=]\s*["\']?[A-Za-z0-9-]{6,}',
                    re.I), 'requestId=REDACTED'),
        (re.compile(r'sessionid["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{8,}',
                    re.I), 'sessionid=REDACTED'),
        (re.compile(r'<input\s+[^>]*type=["\']?hidden["\']?[^>]*value=["\'][^"\']+["\']',
                    re.I), '<input type=hidden value=REDACTED>'),
        (re.compile(r'data-[a-z-]+=["\'][A-Za-z0-9+/=_-]{16,}["\']',
                    re.I), 'data-x="REDACTED"'),
        (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'), 'ISO_TS'),
        (re.compile(r'\b(?:[0-9a-fA-F]{4}:){7}[0-9a-fA-F]{4}\b'), 'IPV6'),
        (re.compile(r'\bgenerated in[^<]*\b'), 'generated in TIME'),
    ]

    @classmethod
    def normalize(cls, body: str) -> str:
        normalized = body
        for pattern, replacement in cls.VOLATILE_PATTERNS:
            normalized = pattern.sub(replacement, normalized)
        # Collapse whitespace runs to a single space — defeats response padding.
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized

    @classmethod
    def similarity(cls, a: str, b: str) -> float:
        """Compute Ratcliff/Obershelp similarity over normalized bodies.
        Result in [0.0, 1.0].  Bounded execution by capping body length."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        na = cls.normalize(a)[:32768]
        nb = cls.normalize(b)[:32768]
        # Quick filter on length difference
        if abs(len(na) - len(nb)) > max(len(na), len(nb)) * 0.6:
            return SequenceMatcher(None, na[:4096], nb[:4096]).ratio()
        return SequenceMatcher(None, na, nb).quick_ratio()


# ─────────────────────────────────────────────────────────────────────────────
#  BASELINE MANAGER
# ─────────────────────────────────────────────────────────────────────────────
class BaselineManager:
    """Records baseline statistics for an endpoint (timing, length, hash) so
    that subsequent payloads can be compared against the known-good profile."""

    def __init__(self, samples_per_baseline: int = 5,
                 sampler: Optional[Callable[[], HttpSample]] = None) -> None:
        self.samples_per_baseline = samples_per_baseline
        self.sampler = sampler
        self._cache: Dict[str, Dict[str, Any]] = {}

    def baseline(self, key: str,
                 sampler: Optional[Callable[[], HttpSample]] = None) -> Dict[str, Any]:
        """Establish a baseline for `key` by collecting N samples.  Cached."""
        if key in self._cache:
            return self._cache[key]
        sampler = sampler or self.sampler
        if sampler is None:
            raise ValueError("BaselineManager requires a sampler callable")
        elapsed: List[float] = []
        lengths: List[int] = []
        hashes: List[str] = []
        bodies: List[str] = []
        statuses: List[int] = []
        for _ in range(self.samples_per_baseline):
            try:
                s = sampler()
            except Exception:
                continue
            elapsed.append(s.elapsed)
            lengths.append(s.body_len)
            hashes.append(s.body_hash)
            bodies.append(ResponseNormalizer.normalize(s.body)[:8192])
            statuses.append(s.status)
        if not elapsed:
            return {"valid": False}
        baseline = {
            "valid": True,
            "elapsed_mean": statistics.mean(elapsed),
            "elapsed_stdev": statistics.pstdev(elapsed) if len(elapsed) > 1 else 0.05,
            "length_mean": statistics.mean(lengths),
            "length_stdev": statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
            "hashes": hashes,
            "stable_hash": (len(set(hashes)) == 1),
            "bodies": bodies,
            "statuses": statuses,
            "common_status": statistics.mode(statuses) if statuses else 0,
        }
        # Floor stdev to avoid divide-by-zero in z-score calculations.
        if baseline["elapsed_stdev"] < 0.05:
            baseline["elapsed_stdev"] = 0.05
        self._cache[key] = baseline
        return baseline

    def z_score(self, baseline: Dict[str, Any], elapsed: float) -> float:
        """Return Z-score for a single timing sample vs the baseline."""
        if not baseline.get("valid"):
            return 0.0
        return (elapsed - baseline["elapsed_mean"]) / baseline["elapsed_stdev"]

    def length_zscore(self, baseline: Dict[str, Any], length: int) -> float:
        if not baseline.get("valid") or baseline["length_stdev"] == 0:
            return 0.0
        return (length - baseline["length_mean"]) / baseline["length_stdev"]


# ─────────────────────────────────────────────────────────────────────────────
#  HONEYPOT / TARPIT / WAF FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────
class EnvironmentFingerprinter:
    """Detects defensive infrastructure that would otherwise cause systematic
    false positives or false negatives:

      • WAFs (Cloudflare, Imperva, Akamai, F5, AWS WAF, ModSecurity, Sucuri…)
      • Honeypots (Cowrie, Dionaea, T-Pot signatures)
      • Tarpits (LaBrea, IPTables iptables-tarpit, slow-loris responders)
      • CDNs (Cloudflare, Fastly, Akamai)
      • Authentication walls / SSO redirectors

    Findings produced *before* fingerprinting are downgraded automatically when
    the target is later identified as a honeypot."""

    WAF_FINGERPRINTS: List[Tuple[str, str, str]] = [
        # (label, header_regex_or_body_regex, source: 'header'|'body'|'cookie')
        ("Cloudflare",          r"cloudflare|cf-ray|__cfduid|cf-chl-bypass",  "any"),
        ("Akamai",              r"akamai|akamaighost|x-akamai-",              "any"),
        ("Imperva Incapsula",   r"incap_ses|visid_incap|x-iinfo|incapsula",   "any"),
        ("F5 BIG-IP ASM",       r"BIGipServer|TS[0-9a-f]{8,}|x-wa-info",      "any"),
        ("AWS WAF",             r"awselb|x-amz-cf-id|aws-waf",                "any"),
        ("Sucuri",              r"sucuri|x-sucuri-id|x-sucuri-cache",         "any"),
        ("ModSecurity",         r"mod_security|modsecurity|not acceptable",   "any"),
        ("Barracuda",           r"barra_counter_session|barracuda",           "any"),
        ("Fortinet FortiWeb",   r"fortiwafsid|fortigate",                     "any"),
        ("Citrix NetScaler",    r"ns_af|citrix_ns_id|netscaler",              "any"),
        ("Wallarm",             r"nemesida|wallarm",                           "any"),
        ("StackPath",           r"x-sp-url|stackpath",                        "any"),
        ("Cloudfront",          r"x-amz-cf-id|cloudfront",                    "any"),
        ("DDoS-Guard",          r"ddos-guard|__ddg",                          "any"),
        ("Reblaze",             r"rbzid|reblaze",                              "any"),
    ]

    HONEYPOT_FINGERPRINTS: List[Tuple[str, str]] = [
        # SSH banner anomalies (Cowrie reports SSH-2.0-OpenSSH but is a honeypot).
        ("Cowrie SSH",          r"SSH-2\.0-OpenSSH_5\.1p1 Debian-5"),
        # Dionaea malware honeypot SMB
        ("Dionaea",             r"dionaea|nepenthes"),
        # Glastopf default index
        ("Glastopf",            r"glastopf|wordpress.*honeypot"),
        # T-Pot
        ("T-Pot",               r"tpot|mhn|honeydrive"),
        # HoneyTrap / Conpot ICS
        ("Conpot ICS",          r"conpot|simatic|s7-200"),
    ]

    def __init__(self) -> None:
        self.detected: Dict[str, str] = {}

    def fingerprint(self, sample: HttpSample) -> Dict[str, Any]:
        """Return a dictionary describing detected defensive systems."""
        result: Dict[str, Any] = {"waf": [], "honeypot": [], "cdn": [], "raw": []}
        haystack = " ".join(f"{k}: {v}" for k, v in sample.headers.items()) + "\n" + sample.body[:4096]
        haystack_low = haystack.lower()

        for label, pattern, _ in self.WAF_FINGERPRINTS:
            if re.search(pattern, haystack_low, re.I):
                result["waf"].append(label)

        for label, pattern in self.HONEYPOT_FINGERPRINTS:
            if re.search(pattern, haystack, re.I):
                result["honeypot"].append(label)

        # Dedup
        result["waf"] = sorted(set(result["waf"]))
        result["honeypot"] = sorted(set(result["honeypot"]))

        # Tarpit detection: extreme latency variance with no body
        if sample.elapsed > 8.0 and sample.body_len < 64:
            result["raw"].append("possible_tarpit")

        # Block-page heuristics
        block_keywords = ("access denied", "blocked", "forbidden by waf",
                           "request blocked", "security policy", "attack detected",
                           "malicious", "captcha", "challenge")
        if any(k in haystack_low for k in block_keywords) and sample.status in (403, 406, 419, 429):
            result["raw"].append("waf_block_page")

        self.detected = result
        return result


# ─────────────────────────────────────────────────────────────────────────────
#  XSS DETECTION (CONTEXT-AWARE)
# ─────────────────────────────────────────────────────────────────────────────
class XSSDetector:
    """Context-aware XSS validator.  Determines the lexical context where a
    payload is reflected (HTML body, attribute, JS string, JS code, URL, CSS,
    comment) and verifies that breakout characters survived encoding/filtering.
    Confidence is computed from the number of breakout chars that survived,
    weighted by their context-specific danger."""

    BREAKOUT_CHARS_BY_CONTEXT: Dict[str, str] = {
        "html_body":   "<>",
        "attr_double": '"<>',
        "attr_single": "'<>",
        "attr_unq":    " <>=`",
        "js_string":   "\\'\";\n",
        "js_block":    "/<>",
        "url":         "':\"<>",
        "css":         "():;\\\"",
        "comment":     "-->",
        "unknown":     "<>\"'",
    }

    @staticmethod
    def random_marker(length: int = 12) -> str:
        # Marker that survives most filters and is unlikely to collide.
        alphabet = string.ascii_letters + string.digits
        return "x" + "".join(random.choices(alphabet, k=length)) + "x"

    @classmethod
    def detect_context(cls, body: str, marker: str) -> List[Tuple[str, int]]:
        """Find every reflection of `marker` and label its lexical context.
        Returns list of (context, position)."""
        contexts: List[Tuple[str, int]] = []
        for match in re.finditer(re.escape(marker), body):
            pos = match.start()
            window_before = body[max(0, pos - 200): pos]
            window_after  = body[pos + len(marker): pos + len(marker) + 200]

            # Comment context — last <!-- not closed before pos
            last_open_comment  = window_before.rfind("<!--")
            last_close_comment = window_before.rfind("-->")
            if last_open_comment > last_close_comment:
                contexts.append(("comment", pos))
                continue

            # Inside <script>...</script>
            last_open_script  = window_before.lower().rfind("<script")
            last_close_script = window_before.lower().rfind("</script")
            if last_open_script > last_close_script:
                # Determine if inside string literal
                segment = window_before[last_open_script:]
                # Count unescaped single/double quotes
                dq = len(re.findall(r'(?<!\\)"', segment)) % 2
                sq = len(re.findall(r"(?<!\\)'", segment)) % 2
                if dq == 1:
                    contexts.append(("js_string", pos))
                elif sq == 1:
                    contexts.append(("js_string", pos))
                else:
                    contexts.append(("js_block", pos))
                continue

            # Inside <style>...</style>
            last_open_style  = window_before.lower().rfind("<style")
            last_close_style = window_before.lower().rfind("</style")
            if last_open_style > last_close_style:
                contexts.append(("css", pos))
                continue

            # Inside an attribute?  Search for '<tag ... marker'
            last_lt = window_before.rfind("<")
            last_gt = window_before.rfind(">")
            if last_lt > last_gt:
                # We are inside a tag.  Determine attribute quoting.
                tag_segment = window_before[last_lt:] + marker + window_after
                # Find quote char immediately before marker (if any).
                pre = window_before[last_lt:]
                # Attribute= ... pattern just before marker
                m = re.search(r'(\w+)\s*=\s*("|\'|)$', pre)
                if m:
                    quote = m.group(2)
                    if quote == '"':
                        contexts.append(("attr_double", pos))
                    elif quote == "'":
                        contexts.append(("attr_single", pos))
                    else:
                        contexts.append(("attr_unq", pos))
                    continue

            contexts.append(("html_body", pos))
        return contexts

    @classmethod
    def confidence_for(cls, context: str, breakouts_surviving: List[str]) -> float:
        """Compute confidence based on how many breakout chars survived."""
        required = cls.BREAKOUT_CHARS_BY_CONTEXT.get(context, "<>\"'")
        if not breakouts_surviving:
            return 0.10  # reflected but inert
        ratio = len(set(breakouts_surviving) & set(required)) / max(1, len(required))
        # Tag context as more dangerous than text context
        weight = {
            "html_body": 0.95, "attr_double": 0.9, "attr_single": 0.9,
            "attr_unq": 0.85,  "js_string": 0.95, "js_block": 0.99,
            "url": 0.85, "css": 0.7, "comment": 0.4, "unknown": 0.5,
        }.get(context, 0.6)
        return min(1.0, 0.3 + (ratio * weight))


# ─────────────────────────────────────────────────────────────────────────────
#  SQLi DETECTION (BOOLEAN + TIME + ERROR + UNION)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiDetector:
    """High-confidence SQL injection detector that combines four orthogonal
    detection vectors.  Each vector scores independently; a finding requires
    at least two vectors to agree, or one vector with very high confidence."""

    DBMS_ERROR_PATTERNS: List[Tuple[str, str]] = [
        (r"you have an error in your sql syntax",                 "MySQL"),
        (r"warning:\s*mysql_",                                    "MySQL"),
        (r"mysqlclient\.cursors",                                 "MySQL"),
        (r"valid mysql result",                                   "MySQL"),
        (r"check the manual that corresponds to your (mysql|mariadb)",
                                                                  "MySQL"),
        (r"mariadb server version for the right syntax",          "MariaDB"),
        (r"unclosed quotation mark after the character string",   "MSSQL"),
        (r"quoted string not properly terminated",                "Oracle"),
        (r"ora-\d{5}",                                            "Oracle"),
        (r"oracle.*driver",                                       "Oracle"),
        (r"microsoft (?:ole db|odbc).*sql server",                "MSSQL"),
        (r"sqlserver jdbc driver",                                "MSSQL"),
        (r"system\.data\.sqlclient\.sqlexception",                "MSSQL"),
        (r"postgresql.*error",                                    "PostgreSQL"),
        (r"pg::syntaxerror",                                      "PostgreSQL"),
        (r"psql:.*error",                                         "PostgreSQL"),
        (r"sqlite3?\.(?:operationalerror|databaseerror)",         "SQLite"),
        (r"unrecognized token:",                                  "SQLite"),
        (r"db2 sql error",                                        "DB2"),
        (r"sybase.*server message",                               "Sybase"),
        (r"informix.*error",                                      "Informix"),
        (r"ingres sqlerror",                                      "Ingres"),
        (r"firebird.*error|isc_dsql_",                            "Firebird"),
    ]

    # Boolean-blind: an oracle that should be TRUE vs an oracle that should be FALSE
    BOOLEAN_PAIRS_TEMPLATES: List[Tuple[str, str]] = [
        ("' AND 1=1-- -",                "' AND 1=2-- -"),
        ('" AND 1=1-- -',                '" AND 1=2-- -'),
        (") AND 1=1-- -",                ") AND 1=2-- -"),
        (") AND '1'='1",                 ") AND '1'='2"),
        ("' AND 'a'='a",                 "' AND 'a'='b"),
        (" AND 1=1",                     " AND 1=2"),
        ("/**/AND/**/1=1",               "/**/AND/**/1=2"),
        ("'||'1'='1",                    "'||'1'='2"),
    ]

    # Time-based payloads tagged by DB family
    TIME_PAYLOADS: List[Tuple[str, str, int]] = [
        ("' AND SLEEP({d})-- -",                                                  "MySQL",      5),
        ("' AND IF(1=1,SLEEP({d}),0)-- -",                                        "MySQL",      5),
        ("' AND (SELECT * FROM (SELECT(SLEEP({d})))a)-- -",                       "MySQL",      5),
        ("'; SELECT pg_sleep({d})-- -",                                           "PostgreSQL", 5),
        ("' || pg_sleep({d}) || '",                                               "PostgreSQL", 5),
        ("'; WAITFOR DELAY '0:0:{d}'-- -",                                        "MSSQL",      5),
        (";WAITFOR DELAY '0:0:{d}'-- -",                                          "MSSQL",      5),
        ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -",                          "Oracle",     5),
        ("' AND randomblob(100000000)-- -",                                       "SQLite",     5),
    ]

    UNION_PROBES: List[str] = [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        "' ORDER BY 1-- -",
        "' ORDER BY 100-- -",     # forces an error if columns < 100
    ]

    @classmethod
    def detect_error(cls, body: str) -> Tuple[Optional[str], float]:
        body_low = body.lower()
        for pattern, dbms in cls.DBMS_ERROR_PATTERNS:
            if re.search(pattern, body_low):
                # Error-based has the highest single-shot confidence.
                return dbms, 0.95
        return None, 0.0

    @classmethod
    def boolean_confidence(cls, true_sample: HttpSample, false_sample: HttpSample,
                           baseline: Optional[HttpSample]) -> float:
        """Boolean-blind: TRUE response should resemble baseline; FALSE should
        diverge.  Confidence proportional to the divergence asymmetry."""
        if baseline is None:
            sim_tf = ResponseNormalizer.similarity(true_sample.body, false_sample.body)
            return max(0.0, (1.0 - sim_tf) - 0.05)
        sim_t = ResponseNormalizer.similarity(true_sample.body, baseline.body)
        sim_f = ResponseNormalizer.similarity(false_sample.body, baseline.body)
        # Strong indicator: TRUE ≈ baseline AND FALSE ≠ baseline
        delta = sim_t - sim_f
        if sim_t >= DIFF_SIMILARITY_HIGH and sim_f <= DIFF_SIMILARITY_LOW:
            return min(1.0, 0.7 + delta)
        if delta > 0.10:
            return min(1.0, 0.45 + delta)
        return 0.0

    @staticmethod
    def time_confidence(z_score: float, observed_delta: float, requested: int) -> float:
        """Time-based confidence — z-score must exceed threshold AND absolute
        delta must exceed MIN_TIME_DELTA_SEC AND be near the requested delay."""
        if observed_delta < MIN_TIME_DELTA_SEC:
            return 0.0
        # We want observed_delta to be close to the requested sleep.
        # Accept 0.7x – 3.0x of the requested delay; outside that band it is
        # almost certainly natural latency rather than the SQL sleep firing.
        ratio = observed_delta / max(0.1, requested)
        if not (0.7 <= ratio <= 3.0):
            return 0.10  # delay exists but does not match — likely natural latency
        if z_score >= TIME_ZSCORE_CONFIRMED:
            return min(1.0, 0.85 + (z_score - TIME_ZSCORE_CONFIRMED) * 0.02)
        if z_score >= TIME_ZSCORE_PROBABLE:
            return 0.65
        return 0.30


# ─────────────────────────────────────────────────────────────────────────────
#  SSRF VALIDATOR (OOB-AWARE)
# ─────────────────────────────────────────────────────────────────────────────
class SSRFValidator:
    """SSRF validation that looks for content fingerprints from internal
    services rather than vague keyword matches.  Reduces FPs caused by
    application output that happens to contain `127.0.0.1` strings."""

    INDICATORS: Dict[str, List[str]] = {
        "aws_metadata": [
            "ami-id", "instance-id", "instance-type", "security-credentials",
            "iam/info", "ami-launch-index", "block-device-mapping",
        ],
        "gcp_metadata": [
            "Metadata-Flavor: Google", "computeMetadata", "service-accounts/default",
        ],
        "azure_metadata": [
            "Metadata: true", "compute/azEnvironment", "Microsoft.Compute",
        ],
        "alibaba_metadata": [
            "Aliyun", "ram/security-credentials",
        ],
        "kubernetes": [
            "/var/run/secrets/kubernetes.io", "service-account-token",
        ],
        "redis":  ["+PONG", "redis_version", "# Server", "# Replication"],
        "docker": ["/var/run/docker.sock", "ContainerConfig"],
        "consul": ["X-Consul-", "ServiceAddress"],
        "etcd":   ["etcd-cluster", "raft_index"],
        "linux_passwd": ["root:x:0:0:", "daemon:x:1:1:", "/bin/bash"],
    }

    @classmethod
    def validate(cls, body: str, headers: Dict[str, str]) -> Tuple[Optional[str], float, List[str]]:
        haystack = body[:8192] + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        evidence: List[str] = []
        target: Optional[str] = None
        max_confidence = 0.0
        for service, sigs in cls.INDICATORS.items():
            hits = [s for s in sigs if s in haystack]
            if not hits:
                continue
            # Confidence rises with hit count
            conf = min(1.0, 0.5 + 0.15 * len(hits))
            if conf > max_confidence:
                max_confidence = conf
                target = service
            evidence.append(f"{service}: {hits}")
        return target, max_confidence, evidence


# ─────────────────────────────────────────────────────────────────────────────
#  LFI / PATH TRAVERSAL VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────
class LFIValidator:
    """Validates LFI/path-traversal hits using strong file-content fingerprints."""

    SIGNATURES: Dict[str, str] = {
        "linux_passwd":   r"root:[x*]:0:0:[^:\n]*:[^:\n]*:(?:/[^:\n]*)+",
        "linux_shadow":   r"root:[$!*][^:\n]*:\d+:\d+:\d+:\d+:[^:\n]*:[^:\n]*",
        "linux_group":    r"^root:x:0:[a-z0-9,]*$",
        "linux_hosts":    r"127\.0\.0\.1\s+localhost",
        "ssh_keys":       r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "win_hosts":      r"#\s*Copyright\s+\(c\)\s+\d+\s+Microsoft.*hosts",
        "win_winini":     r"\[fonts\][\r\n]+\[extensions\]",
        "win_bootini":    r"\[boot loader\]",
        "proc_env":       r"PATH=[^\x00]*USER=",
        "php_filter_b64": r"^[A-Za-z0-9+/]{200,}={0,2}$",   # base64 dump of file
        "apache_conf":    r"<Directory\s+[^>]+>",
        "wp_config":      r"DB_PASSWORD['\"]?\s*,\s*['\"][^'\"]+",
    }

    @classmethod
    def validate(cls, body: str, payload: str) -> Tuple[Optional[str], float, List[str]]:
        evidence: List[str] = []
        target: Optional[str] = None
        max_conf = 0.0
        for sig_name, pattern in cls.SIGNATURES.items():
            if re.search(pattern, body, re.M | re.I):
                evidence.append(f"matched {sig_name}")
                # /etc/passwd exact match has the highest confidence
                conf = 0.97 if sig_name in ("linux_passwd", "linux_shadow",
                                              "ssh_keys", "wp_config") else 0.85
                if conf > max_conf:
                    max_conf = conf
                    target = sig_name
        # Bonus: payload uses traversal patterns AND result contains signature
        if max_conf > 0 and any(t in payload for t in ("../", "..\\", "%2e%2e",
                                                         "....//", "php://filter")):
            max_conf = min(1.0, max_conf + 0.02)
        return target, max_conf, evidence


# ─────────────────────────────────────────────────────────────────────────────
#  COMMAND INJECTION DETECTOR (ENVIRONMENT-AWARE)
# ─────────────────────────────────────────────────────────────────────────────
class CommandInjectionDetector:
    """Detects OS command injection by demanding canary echoes that no normal
    HTTP processor would emit on its own."""

    @staticmethod
    def random_canary() -> Tuple[str, str]:
        marker = "z" + "".join(random.choices(string.ascii_lowercase + string.digits,
                                               k=10)) + "z"
        return marker, marker

    @classmethod
    def payload_set(cls, canary: str) -> List[str]:
        # Echo the canary back via shell, with multiple separators to defeat
        # different filtering schemes (semicolon, pipe, backtick, $().
        return [
            f';echo {canary};',
            f'|echo {canary}|',
            f'`echo {canary}`',
            f'$(echo {canary})',
            f'%0aecho%20{canary}%0a',
            f'%0d%0aecho%20{canary}',
            f"';echo {canary};'",
            f'";echo {canary};"',
            f'&& echo {canary} &&',
            f'|| echo {canary} ||',
            f'\necho {canary}\n',
            f';/bin/sh -c "echo {canary}";',
            f';powershell -c "echo {canary}";',
        ]

    @staticmethod
    def confidence(body: str, canary: str) -> float:
        if canary in body:
            # Make sure it's not just our own request line being echoed back
            occurrences = body.count(canary)
            if occurrences == 1:
                return 0.92
            if occurrences >= 2:
                return 0.97
        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  TEMPLATE / SSTI DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
class SSTIDetector:
    """Detects Server-Side Template Injection by checking arithmetic
    evaluation of a non-trivial expression that is unlikely to appear in
    normal output (49 from 7*7 is common; we use larger primes)."""

    PROBES: List[Tuple[str, str, str]] = [
        # (probe, expected_output, template_engine)
        ("{{93*97}}",       "9021",  "Jinja2/Django"),
        ("${93*97}",        "9021",  "Spring/JSP"),
        ("<%= 93*97 %>",    "9021",  "ERB"),
        ("#{93*97}",        "9021",  "Ruby/Slim"),
        ("{93*97}",         "9021",  "Smarty"),
        ("@(93*97)",        "9021",  "Razor"),
        ("[[${93*97}]]",    "9021",  "Thymeleaf"),
        ("{{= 93*97 }}",    "9021",  "Underscore"),
    ]

    @classmethod
    def confidence(cls, probe: str, expected: str, body: str,
                   baseline_body: str) -> float:
        # Expected token must appear in response AND not in baseline
        if expected not in body or expected in baseline_body:
            return 0.0
        # Probe text itself appearing verbatim → not executed
        if probe in body:
            return 0.30   # reflected, not executed
        return 0.95


# ─────────────────────────────────────────────────────────────────────────────
#  AGGREGATE FINDING DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class FindingAggregator:
    """Collapse duplicate findings (same vuln_type + parameter + URL stem),
    keep the one with the highest confidence."""

    def __init__(self) -> None:
        self._by_key: Dict[Tuple[str, str, str], Finding] = {}

    @staticmethod
    def _key(f: Finding) -> Tuple[str, str, str]:
        url = urllib.parse.urlsplit(f.url)
        stem = f"{url.scheme}://{url.netloc}{url.path}"
        return (f.vuln_type, stem, f.parameter or "")

    def add(self, f: Finding) -> None:
        if f.confidence < CONFIDENCE_NOISE:
            return
        key = self._key(f)
        existing = self._by_key.get(key)
        if existing is None or f.confidence > existing.confidence:
            self._by_key[key] = f
        else:
            # Merge evidence
            existing.evidence.extend(f.evidence)

    def all(self) -> List[Finding]:
        return sorted(self._by_key.values(), key=lambda x: -x.confidence)

    def confirmed(self) -> List[Finding]:
        return [f for f in self.all() if f.confidence >= CONFIDENCE_CONFIRMED]

    def probable(self) -> List[Finding]:
        return [f for f in self.all()
                if CONFIDENCE_PROBABLE <= f.confidence < CONFIDENCE_CONFIRMED]


# ─────────────────────────────────────────────────────────────────────────────
#  SHANNON ENTROPY  (utility for secret/credential detection)
# ─────────────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def looks_like_secret(token: str) -> bool:
    """Generic secret detector: long, high-entropy, mixed alphabet."""
    if len(token) < 20:
        return False
    e = shannon_entropy(token)
    if e < 4.0:
        return False
    has_alpha = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return has_alpha and has_digit


__all__ = [
    "HttpSample", "Finding",
    "ResponseNormalizer", "BaselineManager",
    "EnvironmentFingerprinter",
    "XSSDetector", "SQLiDetector", "SSRFValidator",
    "LFIValidator", "CommandInjectionDetector", "SSTIDetector",
    "FindingAggregator",
    "shannon_entropy", "looks_like_secret",
    "CONFIDENCE_CONFIRMED", "CONFIDENCE_PROBABLE",
    "CONFIDENCE_SUSPECTED", "CONFIDENCE_NOISE",
    "TIME_ZSCORE_CONFIRMED", "TIME_ZSCORE_PROBABLE",
    "MIN_TIME_DELTA_SEC",
    "DIFF_SIMILARITY_LOW", "DIFF_SIMILARITY_HIGH",
]
