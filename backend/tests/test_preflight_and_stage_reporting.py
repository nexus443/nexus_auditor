import copy
import os
import sys
import tempfile
import time
import types
import unittest

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


if __name__ == "__main__":
    unittest.main()
