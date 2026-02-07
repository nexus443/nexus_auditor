import unittest

from backend.scan_mode_controller import ScanModeController


class ScanModeControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = ScanModeController()

    def test_mode_resolution(self):
        self.assertEqual(self.controller.resolve_mode_key(mode_key="rapid"), "rapid")
        self.assertEqual(self.controller.resolve_mode_key(mode_key="devsecops"), "devsecops")
        self.assertEqual(
            self.controller.resolve_mode_key(mode_config={"label": "Scan Profond"}),
            "deep",
        )

    def test_rapid_prioritizes_hotspots(self):
        files = [
            "/repo/src/utils/helpers.py",
            "/repo/src/auth/login_service.py",
            "/repo/tests/auth_spec.py",
            "/repo/src/payment/checkout.ts",
        ]
        ordered = self.controller.prioritize_files(files, "rapid")
        ordered_paths = [entry["path"] for entry in ordered]
        self.assertEqual(ordered_paths[0], "/repo/src/auth/login_service.py")
        self.assertIn("/repo/src/payment/checkout.ts", ordered_paths[:2])

    def test_devsecops_prioritizes_config_and_pipeline_files(self):
        files = [
            "/repo/src/app.py",
            "/repo/.github/workflows/ci.yml",
            "/repo/docker-compose.yml",
            "/repo/requirements.txt",
        ]
        ordered = self.controller.prioritize_files(files, "devsecops")
        ordered_paths = [entry["path"] for entry in ordered]
        top3 = set(ordered_paths[:3])
        self.assertIn("/repo/.github/workflows/ci.yml", top3)
        self.assertIn("/repo/docker-compose.yml", top3)
        self.assertIn("/repo/requirements.txt", top3)

    def test_prompt_templates_are_mode_specific(self):
        rapid_prompt = self.controller.build_analysis_prompt(
            mode_key="rapid",
            filename="a.py",
            content="print('x')",
            language="python",
            chunk_index=1,
            chunk_total=1,
            hotspot_reasons=["hotspot-keyword"],
            cross_file_hints=[],
        )
        deep_prompt = self.controller.build_analysis_prompt(
            mode_key="deep",
            filename="b.py",
            content="print('y')",
            language="python",
            chunk_index=1,
            chunk_total=1,
            hotspot_reasons=[],
            cross_file_hints=["SQL_INJECTION@db.py:42"],
        )
        devsecops_prompt = self.controller.build_analysis_prompt(
            mode_key="devsecops",
            filename="docker-compose.yml",
            content="services:\n  api:\n    image: foo",
            language="config",
            chunk_index=1,
            chunk_total=1,
            hotspot_reasons=[],
            cross_file_hints=[],
        )

        self.assertIn("Mode: RAPID", rapid_prompt)
        self.assertIn("HOTSPOT FOCUS", rapid_prompt)
        self.assertIn("Mode: DEEP", deep_prompt)
        self.assertIn("CROSS-FILE HINTS", deep_prompt)
        self.assertIn("Mode: DEVSECOPS", devsecops_prompt)
        self.assertIn("DEVSECOPS FOCUS", devsecops_prompt)

    def test_cross_file_hints_bounded(self):
        hints = []
        findings = [{"type": "SQL_INJECTION", "line": i} for i in range(1, 20)]
        updated = self.controller.update_cross_file_hints(hints, "app.py", findings, max_hints=12)
        self.assertEqual(len(updated), 12)
        self.assertTrue(updated[-1].startswith("SQL_INJECTION@app.py:"))


if __name__ == "__main__":
    unittest.main()
