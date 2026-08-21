import copy
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")

    class _RequestsError(Exception):
        pass

    def _requests_unavailable(*args, **kwargs):
        raise _RequestsError("requests is unavailable in unit-test sandbox")

    requests_stub.get = _requests_unavailable
    requests_stub.post = _requests_unavailable
    requests_stub.exceptions = types.SimpleNamespace(Timeout=_RequestsError, ConnectionError=_RequestsError)
    sys.modules["requests"] = requests_stub

if "git" not in sys.modules:
    git_stub = types.ModuleType("git")

    class Repo:  # pragma: no cover - only for import compatibility in tests
        @staticmethod
        def clone_from(*args, **kwargs):
            raise RuntimeError("git clone not available in this test context")

    git_stub.Repo = Repo
    sys.modules["git"] = git_stub

if "pydantic" not in sys.modules:
    pydantic_stub = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    def Field(default=None, **kwargs):
        return default

    pydantic_stub.BaseModel = BaseModel
    pydantic_stub.Field = Field
    sys.modules["pydantic"] = pydantic_stub

if "fastapi" not in sys.modules:
    fastapi_stub = types.ModuleType("fastapi")
    fastapi_stub.__path__ = []

    class BackgroundTasks:
        def add_task(self, *args, **kwargs):
            return None

    class HTTPException(Exception):
        def __init__(self, status_code=500, detail=""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(detail)

    class FastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def get(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

    fastapi_stub.FastAPI = FastAPI
    fastapi_stub.BackgroundTasks = BackgroundTasks
    fastapi_stub.HTTPException = HTTPException
    sys.modules["fastapi"] = fastapi_stub

    responses_stub = types.ModuleType("fastapi.responses")

    class _Response:
        def __init__(self, *args, **kwargs):
            pass

    responses_stub.FileResponse = _Response
    responses_stub.JSONResponse = _Response
    responses_stub.HTMLResponse = _Response
    sys.modules["fastapi.responses"] = responses_stub

    middleware_stub = types.ModuleType("fastapi.middleware")
    middleware_stub.__path__ = []
    sys.modules["fastapi.middleware"] = middleware_stub

    cors_stub = types.ModuleType("fastapi.middleware.cors")

    class CORSMiddleware:
        pass

    cors_stub.CORSMiddleware = CORSMiddleware
    sys.modules["fastapi.middleware.cors"] = cors_stub

from backend import backend as backend_module
from backend.analysis_context import AnalysisUnitBuilder, ContextPackBuilder, ReachabilityAnalyzer
from backend.project_graph import ProjectGraphBuilder


class PreflightAndStageReportingTests(unittest.TestCase):
    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))

    def test_collect_scan_candidates_applies_mode_filters(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "src"), exist_ok=True)
            os.makedirs(os.path.join(tmp_dir, "node_modules", "leftpad"), exist_ok=True)

            with open(os.path.join(tmp_dir, "src", "app.py"), "w", encoding="utf-8") as f:
                f.write("def run(user_input):\n    return user_input\n")
            with open(os.path.join(tmp_dir, "src", "package.json"), "w", encoding="utf-8") as f:
                f.write('{"name":"demo"}\n')
            with open(os.path.join(tmp_dir, "node_modules", "leftpad", "index.js"), "w", encoding="utf-8") as f:
                f.write("module.exports = {}\n")
            with open(os.path.join(tmp_dir, "docker-compose.yml"), "w", encoding="utf-8") as f:
                f.write("services:\n  app:\n    image: demo\n")

            deep = backend_module.collect_scan_candidates(tmp_dir, "deep", backend_module.SCAN_MODES["deep"])
            self.assertEqual(deep["files_discovered"], 1)
            self.assertEqual(deep["files_scheduled"], 1)
            self.assertGreater(deep["bytes_scheduled"], 0)

            devsecops = backend_module.collect_scan_candidates(tmp_dir, "devsecops", backend_module.SCAN_MODES["devsecops"])
            self.assertGreaterEqual(devsecops["files_discovered"], 2)
            self.assertGreaterEqual(devsecops["files_scheduled"], 2)

    def test_collect_scan_candidates_excludes_backup_tmp_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            original_env = os.environ.get("NEXUS_MAX_SCAN_FILE_BYTES")
            os.environ["NEXUS_MAX_SCAN_FILE_BYTES"] = "128"
            try:
                os.makedirs(os.path.join(tmp_dir, "src"), exist_ok=True)
                os.makedirs(os.path.join(tmp_dir, "vendor"), exist_ok=True)
                os.makedirs(os.path.join(tmp_dir, ".cache"), exist_ok=True)

                with open(os.path.join(tmp_dir, "src", "ok.py"), "w", encoding="utf-8") as f:
                    f.write("def ok():\n    return 1\n")
                with open(os.path.join(tmp_dir, "src", "service.backup.py"), "w", encoding="utf-8") as f:
                    f.write("def backup_copy():\n    return 1\n")
                with open(os.path.join(tmp_dir, "src", "draft.tmp"), "w", encoding="utf-8") as f:
                    f.write("temporary\n")
                with open(os.path.join(tmp_dir, "src", "huge.py"), "w", encoding="utf-8") as f:
                    f.write("x" * 512)
                with open(os.path.join(tmp_dir, "vendor", "vendored.py"), "w", encoding="utf-8") as f:
                    f.write("def vendored():\n    pass\n")
                with open(os.path.join(tmp_dir, ".cache", "cache.py"), "w", encoding="utf-8") as f:
                    f.write("def cached():\n    pass\n")

                result = backend_module.collect_scan_candidates(tmp_dir, "deep", backend_module.SCAN_MODES["deep"])
            finally:
                if original_env is None:
                    os.environ.pop("NEXUS_MAX_SCAN_FILE_BYTES", None)
                else:
                    os.environ["NEXUS_MAX_SCAN_FILE_BYTES"] = original_env

            scheduled_paths = {entry["path"] for entry in result["file_entries"]}
            self.assertIn(os.path.join(tmp_dir, "src", "ok.py"), scheduled_paths)
            self.assertNotIn(os.path.join(tmp_dir, "src", "service.backup.py"), scheduled_paths)
            self.assertNotIn(os.path.join(tmp_dir, "src", "draft.tmp"), scheduled_paths)
            self.assertNotIn(os.path.join(tmp_dir, "src", "huge.py"), scheduled_paths)
            self.assertNotIn(os.path.join(tmp_dir, "vendor", "vendored.py"), scheduled_paths)
            self.assertNotIn(os.path.join(tmp_dir, ".cache", "cache.py"), scheduled_paths)
            self.assertGreaterEqual(result.get("excluded_policy_files", 0), 2)
            self.assertGreaterEqual(result.get("excluded_oversized_files", 0), 1)
            self.assertEqual(result.get("max_file_size_bytes"), 128)

    def test_build_scan_preflight_returns_eta_and_stage_breakdown(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "service"), exist_ok=True)

            with open(os.path.join(tmp_dir, "service", "main.py"), "w", encoding="utf-8") as f:
                f.write("def hello(name):\n    return f'hi {name}'\n")
            with open(os.path.join(tmp_dir, "service", "auth.py"), "w", encoding="utf-8") as f:
                f.write("def login(token):\n    return token\n")

            preflight = backend_module.build_scan_preflight(
                target=tmp_dir,
                profile_key="balanced",
                mode_key="deep",
                ollama_mode="auto",
                ollama_url=None,
            )

            self.assertEqual(preflight["stage_sequence"], list(backend_module.PIPELINE_STAGES))
            self.assertEqual(preflight["mode"], "deep")
            self.assertGreaterEqual(preflight["files"]["scheduled"], 2)
            self.assertGreaterEqual(preflight["chunking"]["chunks_estimated_total"], 1)
            self.assertGreater(preflight["eta"]["seconds"], 0)
            for stage in backend_module.PIPELINE_STAGES:
                self.assertIn(stage, preflight["eta"]["by_stage_seconds"])

    def test_stage_report_tracks_active_completed_and_terminal_state(self):
        backend_module.scan_state["stage_report"] = backend_module.init_stage_report("idle")
        started_at = time.time() - 0.02

        backend_module.start_scan_stage("normalize")
        backend_module.end_scan_stage("normalize", started_at)

        report = backend_module.scan_state["stage_report"]
        self.assertEqual(report["stage_status"]["normalize"], "completed")
        self.assertIn("normalize", report["completed"])

        backend_module.mark_stage_terminal_state("completed")
        report = backend_module.scan_state["stage_report"]
        self.assertEqual(report["terminal_state"], "completed")
        self.assertEqual(report["stage_status"]["report"], "completed")

    def test_preflight_repo_stats(self):
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return {"models": [{"name": "qwen2.5-coder:14b"}]}

        with tempfile.TemporaryDirectory() as tmp_dir:
            original_env = os.environ.get("NEXUS_MAX_SCAN_FILE_BYTES")
            os.environ["NEXUS_MAX_SCAN_FILE_BYTES"] = "128"
            try:
                os.makedirs(os.path.join(tmp_dir, "src"), exist_ok=True)
                os.makedirs(os.path.join(tmp_dir, "node_modules", "leftpad"), exist_ok=True)

                with open(os.path.join(tmp_dir, "src", "app.py"), "w", encoding="utf-8") as f:
                    f.write("def ok():\n    return 1\n")
                with open(os.path.join(tmp_dir, "src", "tmp.backup.py"), "w", encoding="utf-8") as f:
                    f.write("def backup():\n    return 0\n")
                with open(os.path.join(tmp_dir, "src", "notes.txt"), "w", encoding="utf-8") as f:
                    f.write("notes\n")
                with open(os.path.join(tmp_dir, "src", "huge.py"), "w", encoding="utf-8") as f:
                    f.write("x" * 1024)
                with open(os.path.join(tmp_dir, "node_modules", "leftpad", "index.js"), "w", encoding="utf-8") as f:
                    f.write("module.exports = {}\n")

                with patch.object(backend_module.requests, "get", return_value=FakeResponse()):
                    payload = backend_module.build_scan_preflight_summary(
                        target=tmp_dir,
                        profile_key="balanced",
                        mode_key="deep",
                        ollama_mode="auto",
                        ollama_url=None,
                    )
            finally:
                if original_env is None:
                    os.environ.pop("NEXUS_MAX_SCAN_FILE_BYTES", None)
                else:
                    os.environ["NEXUS_MAX_SCAN_FILE_BYTES"] = original_env

        repo_stats = payload["repo_stats"]
        self.assertGreaterEqual(repo_stats["total_files"], 4)
        self.assertGreaterEqual(repo_stats["analyzable_files"], 1)
        self.assertGreaterEqual(repo_stats["excluded_files"], 2)
        self.assertGreater(repo_stats["total_bytes_est"], 0)
        self.assertIsInstance(repo_stats["excluded_reasons"], list)
        self.assertLessEqual(len(repo_stats["excluded_reasons"]), 5)

    def test_preflight_profile_params(self):
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return {"models": [{"name": "qwen2.5-coder:32b"}, {"name": "qwen2.5-coder:14b"}]}

        with tempfile.TemporaryDirectory() as tmp_dir:
            with open(os.path.join(tmp_dir, "main.py"), "w", encoding="utf-8") as f:
                f.write("def run():\n    return True\n")

            with patch.object(backend_module.requests, "get", return_value=FakeResponse()):
                payload = backend_module.build_scan_preflight_summary(
                    target=tmp_dir,
                    profile_key="elite",
                    mode_key="deep",
                    ollama_mode="auto",
                    ollama_url=None,
                )

        profile_effective = payload["profile_effective"]
        ollama_context = payload["ollama_context"]
        self.assertEqual(profile_effective["profile_name"], "elite")
        self.assertGreater(profile_effective["target_chunk_tokens"], 0)
        self.assertGreater(profile_effective["connect_timeout_s"], 0)
        self.assertGreater(profile_effective["read_timeout_s"], 0)
        self.assertGreaterEqual(profile_effective["max_concurrency"], 1)
        self.assertGreater(profile_effective["global_scan_timeout_s"], 0)
        self.assertEqual(profile_effective["strict_evidence"], backend_module.STRICT_EVIDENCE)
        self.assertTrue(ollama_context["reachable"])
        self.assertGreaterEqual(len(ollama_context["tags"]), 1)

    def test_preflight_warnings(self):
        with patch.dict(
            backend_module.POWER_PROFILES,
            {"eco": {**backend_module.POWER_PROFILES["eco"], "model": "qwen2.5-coder:14b"}},
            clear=False,
        ):
            payload = backend_module.build_scan_preflight_summary(
                target="https://github.com/example/repo.git",
                profile_key="eco",
                mode_key="deep",
                ollama_mode="remote",
                ollama_url="https://proxy.runpod.io",
            )

        warnings = payload["warnings"]
        self.assertTrue(any("524" in w for w in warnings))
        self.assertTrue(any("Eco profile with model > 8B" in w for w in warnings))
        self.assertTrue(any("partial" in w.lower() for w in warnings))


class AnalysisUnitEngineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "project_graph_python")
        )
        graph = ProjectGraphBuilder(cls.fixture_root).build()
        reachability = ReachabilityAnalyzer().analyze(graph)
        cls.unit = next(
            unit for unit in AnalysisUnitBuilder().build(graph, reachability)
            if unit.entrypoint == "POST /run"
        )

    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))

    def test_stable_engine_scans_context_pack_and_preserves_graph_metadata(self):
        pack = ContextPackBuilder().build(self.unit)
        engine = backend_module.StableEngine(
            backend_module.POWER_PROFILES["balanced"],
            backend_module.SCAN_MODES["deep"],
            budget_plan={"retries": 1, "enable_verify_pass": False},
            profile_name="balanced",
        )
        model_result = {
            "data": [{
                "title": "Command injection",
                "type": "COMMAND_INJECTION",
                "severity": "High",
                "confidence": 92,
                "file": "app/repository.py",
                "evidence": "return os.system(user_input)",
                "description": "User-controlled input reaches a command shell",
                "impact": "Command execution",
                "recommendation": "Avoid invoking a shell",
            }],
            "raw": "[]",
        }
        backend_module.scan_state["should_stop"] = False
        with patch.object(engine, "call_ollama", return_value=model_result), patch.object(
            backend_module,
            "apply_mode_filters",
            side_effect=lambda findings, *_args, **_kwargs: findings,
        ):
            findings = engine.scan_analysis_unit(self.unit, pack, {"mode_key": "deep"})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], "app/repository.py")
        self.assertEqual(findings[0]["analysis_unit_id"], self.unit.id)
        self.assertEqual(findings[0]["reachability"], "confirmed")
        self.assertEqual(findings[0]["call_path"][:3], self.unit.call_path[:3])

    def test_model_role_contract_defaults_to_current_model(self):
        profile = dict(backend_module.POWER_PROFILES["eco"])
        engine = backend_module.StableEngine(profile, backend_module.SCAN_MODES["rapid"])
        self.assertEqual(
            engine.model_roles,
            {
                "understanding_model": profile["model"],
                "security_model": profile["model"],
                "verifier_model": profile["model"],
            },
        )

    def test_run_scan_prefers_analysis_unit_and_skips_covered_file_fallback(self):
        class FakeEngine:
            unit_entrypoints = []
            file_paths = []

            def __init__(self, *args, **kwargs):
                pass

            def scan_analysis_unit(self, unit, **kwargs):
                self.unit_entrypoints.append(unit.entrypoint)
                return []

            def scan_file(self, filepath, filename, analysis_context=None):
                self.file_paths.append(filepath)
                return []

        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "app.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "from fastapi import FastAPI\n"
                    "app = FastAPI()\n\n"
                    "@app.get('/health')\n"
                    "def health():\n"
                    "    return {'ok': True}\n"
                )
            with patch.object(backend_module, "ensure_model_available", return_value=True), patch.object(
                backend_module, "StableEngine", FakeEngine
            ), patch.object(backend_module, "persist_scan_state"), patch.object(
                backend_module, "save_to_history"
            ):
                backend_module.run_scan(repo_dir, "balanced", "deep", scan_id="graph-unit-test")

        self.assertEqual(FakeEngine.unit_entrypoints, ["GET /health"])
        self.assertEqual(FakeEngine.file_paths, [])
        understanding = backend_module.scan_state.get("application_understanding", {})
        self.assertEqual(understanding.get("status"), "ready")
        self.assertEqual(understanding.get("analysis_units", {}).get("runtime"), 1)


if __name__ == "__main__":
    unittest.main()

