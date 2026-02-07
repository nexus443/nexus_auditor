import unittest

from backend.chunker import (
    build_chunk_plan,
    compute_chunk_token_budget,
    compute_overlap_tokens,
    detect_language,
)


PROFILE_ECO = {"num_ctx": 8192, "num_predict": 1024}
PROFILE_TITAN = {"num_ctx": 65536, "num_predict": 8192}

MODE_RAPID = {"label": "Scan Rapide", "num_predict_override": 256}
MODE_DEEP = {"label": "Scan Profond", "num_predict_override": None}
MODE_DEVSECOPS = {"label": "DevSecOps (CI/CD)", "num_predict_override": None}


def build_python_fixture() -> str:
    block = "\n".join([f"    value += {i}" for i in range(35)])
    return f"""
import os
import json

def func_a(value):
{block}
    return value

class Demo:
    def method_b(self, value):
{block}
        return value

def func_c(value):
{block}
    return value
"""


class ChunkerTests(unittest.TestCase):
    def test_detect_language(self):
        self.assertEqual(detect_language("service.py"), "python")
        self.assertEqual(detect_language("client.tsx"), "typescript")
        self.assertEqual(detect_language("Dockerfile"), "config")
        self.assertEqual(detect_language("notes.txt"), "text")

    def test_dynamic_budget_depends_on_profile_and_mode(self):
        eco_rapid = compute_chunk_token_budget(PROFILE_ECO, MODE_RAPID)
        eco_deep = compute_chunk_token_budget(PROFILE_ECO, MODE_DEEP)
        titan_deep = compute_chunk_token_budget(PROFILE_TITAN, MODE_DEEP)

        self.assertLess(eco_rapid, eco_deep)
        self.assertLess(eco_deep, titan_deep)
        self.assertGreaterEqual(eco_rapid, 256)

    def test_overlap_is_mode_adaptive(self):
        budget = 3000
        rapid = compute_overlap_tokens(budget, MODE_RAPID)
        deep = compute_overlap_tokens(budget, MODE_DEEP)
        devsecops = compute_overlap_tokens(budget, MODE_DEVSECOPS)

        self.assertLess(rapid, deep)
        self.assertLess(deep, devsecops)

    def test_python_chunks_by_units_when_heuristic_is_reliable(self):
        content = build_python_fixture()
        profile = {"num_ctx": 1024, "num_predict": 128}
        mode = {"label": "Scan Profond"}

        plan = build_chunk_plan(content, "fixture.py", profile, mode)

        self.assertEqual(plan["language"], "python")
        self.assertIn(plan["strategy"], {"units", "single"})
        self.assertGreaterEqual(len(plan["chunks"]), 1)

        if plan["strategy"] == "units":
            joined = "\n".join(chunk["content"] for chunk in plan["chunks"])
            self.assertIn("def func_a", joined)
            self.assertIn("class Demo", joined)

    def test_fallback_block_split_and_overlap(self):
        long_text = ("lorem ipsum dolor sit amet consectetur adipiscing elit\n" * 600).strip()
        profile = {"num_ctx": 2048, "num_predict": 256}
        mode = {"label": "Scan Profond"}

        plan = build_chunk_plan(long_text, "README.txt", profile, mode)
        self.assertIn(plan["strategy"], {"blocks", "single", "fallback"})
        self.assertGreaterEqual(len(plan["chunks"]), 1)

        if len(plan["chunks"]) >= 2:
            c1 = plan["chunks"][0]["content"]
            c2 = plan["chunks"][1]["content"]
            # Overlap attendu en deep mode sur split blocks.
            self.assertTrue(c1[-80:] in c2 or c1[-40:] in c2)

    def test_rapid_mode_limits_chunk_count(self):
        content = build_python_fixture() * 8
        profile = {"num_ctx": 2048, "num_predict": 256}
        mode = {"label": "Scan Rapide", "num_predict_override": 256}

        plan = build_chunk_plan(content, "fixture.py", profile, mode)
        self.assertEqual(plan["max_chunks"], 1)
        self.assertEqual(len(plan["chunks"]), 1)


if __name__ == "__main__":
    unittest.main()
