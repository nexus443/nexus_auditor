import unittest

from backend.llm_budget_controller import LLMBudgetController


POWER_PROFILES = {
    "eco": {"num_ctx": 8192, "num_predict": 1024, "timeout": 60, "parallel_files": 1},
    "balanced": {"num_ctx": 16384, "num_predict": 2048, "timeout": 90, "parallel_files": 1},
    "elite": {"num_ctx": 32768, "num_predict": 4096, "timeout": 180, "parallel_files": 2},
    "titan": {"num_ctx": 65536, "num_predict": 8192, "timeout": 300, "parallel_files": 4},
}

SCAN_MODES = {
    "rapid": {"label": "Scan Rapide", "num_predict_override": 256, "max_time_per_file": 20, "min_confidence": 50},
    "deep": {"label": "Scan Profond", "num_predict_override": None, "max_time_per_file": 60, "min_confidence": 35},
    "devsecops": {"label": "DevSecOps", "num_predict_override": None, "max_time_per_file": 120, "min_confidence": 30},
}


class LLMBudgetControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = LLMBudgetController()

    def compute(self, profile: str, mode: str, ollama_mode: str = "auto"):
        return self.controller.compute_plan(
            profile_key=profile,
            mode_key=mode,
            profile_config=POWER_PROFILES[profile],
            mode_config=SCAN_MODES[mode],
            ollama_mode=ollama_mode,
        )

    def test_profile_scaling_context_output(self):
        eco = self.compute("eco", "deep")
        balanced = self.compute("balanced", "deep")
        elite = self.compute("elite", "deep")
        titan = self.compute("titan", "deep")

        self.assertLess(eco["max_context_tokens"], balanced["max_context_tokens"])
        self.assertLess(balanced["max_context_tokens"], elite["max_context_tokens"])
        self.assertLess(elite["max_context_tokens"], titan["max_context_tokens"])

        self.assertLess(eco["max_output_tokens"], balanced["max_output_tokens"])
        self.assertLess(balanced["max_output_tokens"], elite["max_output_tokens"])
        self.assertLess(elite["max_output_tokens"], titan["max_output_tokens"])

    def test_mode_override_and_early_exit(self):
        rapid = self.compute("balanced", "rapid")
        deep = self.compute("balanced", "deep")

        self.assertEqual(rapid["max_output_tokens"], 256)
        self.assertEqual(rapid["early_exit_strategy"], "first_high_confidence")
        self.assertEqual(deep["early_exit_strategy"], "none")

    def test_verify_pass_only_for_elite_titan_deepish_modes(self):
        eco = self.compute("eco", "deep")
        elite_rapid = self.compute("elite", "rapid")
        elite_deep = self.compute("elite", "deep")
        titan_devsecops = self.compute("titan", "devsecops")

        self.assertFalse(eco["enable_verify_pass"])
        self.assertFalse(elite_rapid["enable_verify_pass"])
        self.assertTrue(elite_deep["enable_verify_pass"])
        self.assertTrue(titan_devsecops["enable_verify_pass"])
        self.assertEqual(elite_deep["analysis_passes"], 2)

    def test_remote_plan_adjusts_concurrency_timeout_retries(self):
        auto_plan = self.compute("titan", "deep", ollama_mode="auto")
        remote_plan = self.compute("titan", "deep", ollama_mode="remote")

        self.assertLessEqual(remote_plan["concurrency"], auto_plan["concurrency"])
        self.assertGreaterEqual(remote_plan["timeout_s"], auto_plan["timeout_s"])
        self.assertGreaterEqual(remote_plan["connect_timeout_s"], auto_plan["connect_timeout_s"])
        self.assertGreaterEqual(remote_plan["read_timeout_s"], auto_plan["read_timeout_s"])
        self.assertGreaterEqual(remote_plan["retries"], auto_plan["retries"])


if __name__ == "__main__":
    unittest.main()
