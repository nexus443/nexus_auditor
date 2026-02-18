from typing import Dict


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


class LLMBudgetController:
    """Décide des paramètres LLM à partir du profil de puissance et du mode de scan."""

    def compute_plan(
        self,
        profile_key: str,
        mode_key: str,
        profile_config: Dict,
        mode_config: Dict,
        ollama_mode: str = "auto",
    ) -> Dict:
        num_ctx = int(profile_config.get("num_ctx", 8192))
        base_output = int(profile_config.get("num_predict", 1024))
        mode_output = mode_config.get("num_predict_override")
        max_output_tokens = int(mode_output if mode_output is not None else base_output)

        mode_time_budget = int(mode_config.get("max_time_per_file", profile_config.get("timeout", 90)))
        profile_timeout = int(profile_config.get("timeout", 90))
        timeout_s = int(_clamp(profile_timeout, 20, max(mode_time_budget, profile_timeout)))

        profile_concurrency = int(profile_config.get("parallel_files", 1))
        if mode_key == "rapid":
            concurrency = max(1, min(profile_concurrency, 2))
        elif mode_key == "deep":
            concurrency = max(1, profile_concurrency)
        else:  # devsecops
            concurrency = max(1, profile_concurrency + 1)

        if ollama_mode == "remote":
            concurrency = max(1, concurrency - 1)
            timeout_s = int(round(timeout_s * 1.35))
        read_timeout_s = int(timeout_s)
        connect_timeout_s = int(_clamp(read_timeout_s * 0.15, 3, 12))
        if ollama_mode == "remote":
            connect_timeout_s = max(connect_timeout_s, 8)

        temp_map = {
            "eco": 0.03,
            "balanced": 0.06,
            "elite": 0.08,
            "titan": 0.10,
        }
        top_p_map = {
            "eco": 0.80,
            "balanced": 0.85,
            "elite": 0.90,
            "titan": 0.92,
        }
        retries_map = {
            "eco": 1,
            "balanced": 1,
            "elite": 2,
            "titan": 2,
        }

        retries = retries_map.get(profile_key, 1)
        if ollama_mode == "remote":
            retries = min(3, retries + 1)

        backoff_map = {
            "eco": 1.25,
            "balanced": 1.50,
            "elite": 1.75,
            "titan": 2.00,
        }
        backoff_factor = float(backoff_map.get(profile_key, 1.5))

        analysis_passes = 2 if profile_key in {"elite", "titan"} and mode_key in {"deep", "devsecops"} else 1
        enable_verify_pass = analysis_passes > 1

        if mode_key == "rapid":
            early_exit_strategy = "first_high_confidence"
            early_exit_confidence = max(55, int(mode_config.get("min_confidence", 50)))
        else:
            early_exit_strategy = "none"
            early_exit_confidence = 0

        max_context_tokens = int(_clamp(num_ctx, 1024, 131072))
        verify_max_output_tokens = int(_clamp(max_output_tokens * 0.4, 192, 1024))

        return {
            "profile": profile_key,
            "mode": mode_key,
            "max_context_tokens": max_context_tokens,
            "max_output_tokens": max_output_tokens,
            "temperature": float(temp_map.get(profile_key, 0.06)),
            "top_p": float(top_p_map.get(profile_key, 0.85)),
            "concurrency": int(concurrency),
            "timeout_s": int(timeout_s),
            "connect_timeout_s": int(connect_timeout_s),
            "read_timeout_s": int(read_timeout_s),
            "retries": int(retries),
            "retry_backoff_factor": float(backoff_factor),
            "early_exit_strategy": early_exit_strategy,
            "early_exit_confidence": int(early_exit_confidence),
            "analysis_passes": int(analysis_passes),
            "enable_verify_pass": bool(enable_verify_pass),
            "verify_max_output_tokens": int(verify_max_output_tokens),
            "verify_retries": 1 if enable_verify_pass else 0,
            "verify_temperature": 0.0,
            "verify_top_p": 0.70,
        }
