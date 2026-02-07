import unittest

from backend.aggregation import aggregate_findings, build_signature, ensure_proof


def vuln_template(**overrides):
    base = {
        "file": "service.py",
        "filepath": "/repo/service.py",
        "title": "SQL Injection",
        "type": "SQL_INJECTION",
        "severity": "High",
        "line": 12,
        "line_end": 12,
        "evidence": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
        "description": "Unsanitized input reaches SQL query",
        "fix": "Use parameterized queries",
        "confidence": 78.0,
        "snippet": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
        "impact": "Database disclosure",
        "chunk_index": 1,
        "chunk_refs": [1],
        "symbol": "get_user",
        "source": "user_input",
        "sink": "database_query",
    }
    base.update(overrides)
    return base


class AggregationTests(unittest.TestCase):
    def test_signature_includes_type_file_symbol_source_sink(self):
        v = vuln_template()
        sig = build_signature(v)
        self.assertIn("SQL_INJECTION", sig)
        self.assertIn("/repo/service.py", sig)
        self.assertIn("get_user", sig)
        self.assertIn("database_query", sig)
        self.assertIn("user_input", sig)

    def test_dedup_and_merge_multi_chunk(self):
        v1 = vuln_template(line=12, line_end=12, confidence=72.0, chunk_index=1, chunk_refs=[1])
        v2 = vuln_template(line=18, line_end=21, confidence=84.0, chunk_index=2, chunk_refs=[2], snippet="...longer snippet...")

        merged = aggregate_findings([v1, v2], profile_key="balanced", verify_expected=False)
        self.assertEqual(len(merged), 1)

        finding = merged[0]
        self.assertEqual(finding["line"], 12)
        self.assertEqual(finding["line_end"], 21)
        self.assertEqual(finding["chunk_refs"], [1, 2])
        self.assertEqual(finding["merged_from"], 2)
        self.assertGreaterEqual(finding["confidence"], 70.0)

    def test_no_merge_when_signature_differs(self):
        v1 = vuln_template(type="SQL_INJECTION", symbol="get_user")
        v2 = vuln_template(type="XSS", symbol="render_profile")
        merged = aggregate_findings([v1, v2], profile_key="balanced", verify_expected=False)
        self.assertEqual(len(merged), 2)

    def test_confidence_calibration_eco_heuristic(self):
        weak_proof = vuln_template(
            confidence=90.0,
            line=None,
            line_end=None,
            snippet="",
            evidence="",
            needs_manual_review=True,
            evidence_missing=True,
        )
        calibrated = aggregate_findings([weak_proof], profile_key="eco", verify_expected=False)[0]
        self.assertLess(calibrated["confidence"], 90.0)

    def test_confidence_calibration_elite_requires_proof(self):
        unverified = vuln_template(confidence=80.0, verification_status="unverified")
        downgraded = aggregate_findings([unverified], profile_key="elite", verify_expected=True)[0]
        self.assertLess(downgraded["confidence"], 80.0)

    def test_proof_always_present(self):
        item = ensure_proof(vuln_template(line=None, line_end=None, snippet="", evidence=""))
        self.assertIn("proof", item)
        self.assertEqual(item["proof"]["path"], "/repo/service.py")
        self.assertIsNotNone(item["proof"]["snippet"])


if __name__ == "__main__":
    unittest.main()
