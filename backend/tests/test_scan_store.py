import asyncio
import copy
import os
import sys
import tempfile
import types
import unittest
from collections import deque

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


class DummyBackgroundTasks:
    def __init__(self):
        self.calls = []

    def add_task(self, fn, *args, **kwargs):
        self.calls.append((fn, args, kwargs))


class ScanStoreTests(unittest.TestCase):
    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)
        self._saved_scan_state_dir = backend_module.SCAN_STATE_DIR
        self._saved_latest_pointer = backend_module.LATEST_SCAN_POINTER_FILE
        self._tmpdir_ctx = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmpdir_ctx.name
        backend_module.SCAN_STATE_DIR = self.tmpdir
        backend_module.LATEST_SCAN_POINTER_FILE = os.path.join(self.tmpdir, "latest_scan_id.txt")

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))
        backend_module.SCAN_STATE_DIR = self._saved_scan_state_dir
        backend_module.LATEST_SCAN_POINTER_FILE = self._saved_latest_pointer
        self._tmpdir_ctx.cleanup()

    def test_scan_store_atomic_persist_and_load(self):
        state = backend_module.new_scan_state()
        state.update({"id": "scan_atomic_1", "is_scanning": True, "progress": 42})
        state["logs"] = deque([{"msg": "hello"}], maxlen=backend_module.LOGS_MAXLEN)

        backend_module.persist_scan_state(state)

        scan_file = backend_module._scan_state_file_path("scan_atomic_1")
        self.assertTrue(os.path.exists(scan_file))
        self.assertEqual(backend_module.get_latest_scan_id(), "scan_atomic_1")
        self.assertFalse(any(name.startswith("scan_scan_atomic_1.json.tmp.") for name in os.listdir(self.tmpdir)))

        loaded = backend_module.load_scan_state_from_disk("scan_atomic_1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["id"], "scan_atomic_1")
        self.assertEqual(loaded["progress"], 42)
        self.assertIsInstance(loaded["logs"], deque)
        self.assertEqual(len(loaded["logs"]), 1)

    def test_status_without_scan_id_returns_latest_scan(self):
        state = backend_module.new_scan_state()
        state.update({"id": "scan_latest_1", "is_scanning": True, "current_stage": "analyze"})
        backend_module.persist_scan_state(state)

        result = asyncio.run(backend_module.get_status())

        self.assertEqual(result["id"], "scan_latest_1")
        self.assertIn("stage_report", result)

    def test_stop_without_scan_id_stops_latest_scan(self):
        state = backend_module.new_scan_state()
        state.update({"id": "scan_stop_1", "is_scanning": True, "current_stage": "analyze"})
        backend_module.persist_scan_state(state)

        result = asyncio.run(backend_module.stop_scan())
        self.assertTrue(result["success"])
        self.assertEqual(result["scan_id"], "scan_stop_1")

        stopped = backend_module.load_scan_state_from_disk("scan_stop_1")
        self.assertTrue(stopped["should_stop"])
        self.assertFalse(stopped["is_scanning"])
        self.assertEqual(stopped["current_stage"], "stopped")

    def test_start_scan_returns_scan_id_and_persists_initial_state(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(backend_module.new_scan_state())

        request = backend_module.ScanRequest(
            target=".",
            profile="balanced",
            mode="deep",
            ollama_mode="auto",
            ollama_url=None,
        )
        bg = DummyBackgroundTasks()

        result = asyncio.run(backend_module.start_scan(request, bg))

        self.assertTrue(result["success"])
        self.assertIn("scan_id", result)
        self.assertEqual(result["status"], "started")
        self.assertEqual(len(bg.calls), 1)

        created = backend_module.load_scan_state_from_disk(result["scan_id"])
        self.assertIsNotNone(created)
        self.assertEqual(created["id"], result["scan_id"])
        self.assertTrue(created["is_scanning"])


if __name__ == "__main__":
    unittest.main()
