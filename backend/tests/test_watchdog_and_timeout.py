import copy
import os
import sys
import tempfile
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

    class Repo:  # pragma: no cover
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


class WatchdogAndTimeoutTests(unittest.TestCase):
    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)
        self._saved_scan_state_dir = backend_module.SCAN_STATE_DIR
        self._saved_latest_pointer = backend_module.LATEST_SCAN_POINTER_FILE
        self._tmpdir_ctx = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmpdir_ctx.name
        backend_module.SCAN_STATE_DIR = self.tmpdir
        backend_module.LATEST_SCAN_POINTER_FILE = os.path.join(self.tmpdir, "latest_scan_id.txt")
        backend_module.scan_state.clear()
        backend_module.scan_state.update(backend_module.new_scan_state())

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))
        backend_module.SCAN_STATE_DIR = self._saved_scan_state_dir
        backend_module.LATEST_SCAN_POINTER_FILE = self._saved_latest_pointer
        self._tmpdir_ctx.cleanup()

    def test_run_scan_marks_failed_on_exception_and_unsets_scanning(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write("def run():\n    return 1\n")

            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "collect_scan_candidates", side_effect=RuntimeError("boom collect")):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="balanced",
                    mode_key="deep",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_watchdog_err",
                )

        self.assertEqual(backend_module.scan_state.get("current_stage"), "failed")
        self.assertFalse(backend_module.scan_state.get("is_scanning"))
        self.assertTrue(backend_module.scan_state.get("should_stop"))
        self.assertIn("boom collect", str(backend_module.scan_state.get("error", "")))

        persisted = backend_module.load_scan_state_from_disk("scan_watchdog_err")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.get("current_stage"), "failed")
        self.assertFalse(persisted.get("is_scanning"))

    def test_run_scan_marks_failed_when_global_timeout_is_reached(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            with open(os.path.join(repo_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write("def run():\n    return 1\n")

            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "ensure_scan_within_deadline", side_effect=TimeoutError("Global scan timeout reached during initialization")):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="eco",
                    mode_key="rapid",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_watchdog_timeout",
                )

        self.assertEqual(backend_module.scan_state.get("current_stage"), "failed")
        self.assertFalse(backend_module.scan_state.get("is_scanning"))
        self.assertTrue(backend_module.scan_state.get("should_stop"))
        self.assertIn("Global scan timeout", str(backend_module.scan_state.get("error", "")))

        persisted = backend_module.load_scan_state_from_disk("scan_watchdog_timeout")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.get("current_stage"), "failed")
        self.assertFalse(persisted.get("is_scanning"))


if __name__ == "__main__":
    unittest.main()
