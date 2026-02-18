import json
import os
import sys
import tempfile
import threading
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


class HistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self._saved_history_file = backend_module.HISTORY_FILE
        self._tmpdir_ctx = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmpdir_ctx.name
        backend_module.HISTORY_FILE = os.path.join(self.tmpdir, "audit_history.json")

    def tearDown(self):
        backend_module.HISTORY_FILE = self._saved_history_file
        self._tmpdir_ctx.cleanup()

    def test_save_to_history_is_thread_safe_and_atomic(self):
        def worker(idx: int):
            backend_module.save_to_history(
                {
                    "id": f"scan-{idx}",
                    "date": "2026-02-18T00:00:00",
                    "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                }
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(60)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(backend_module.HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)

        self.assertIsInstance(history, list)
        self.assertLessEqual(len(history), 50)
        self.assertTrue(all(isinstance(item, dict) for item in history))

        leftovers = [name for name in os.listdir(self.tmpdir) if ".tmp." in name]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
