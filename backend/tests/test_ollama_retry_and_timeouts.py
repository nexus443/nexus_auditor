import copy
import sys
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


class FakeHTTPResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return dict(self._payload)


class OllamaRetryAndTimeoutTests(unittest.TestCase):
    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))

    @staticmethod
    def _build_engine(budget_plan=None):
        profile = {
            "model": "qwen2.5-coder:32b",
            "timeout": 120,
            "num_ctx": 32768,
            "num_predict": 4096,
        }
        mode = {"label": "Scan Profond", "max_time_per_file": 60}
        return backend_module.StableEngine(
            profile,
            mode,
            budget_plan=budget_plan or {},
            ollama_base_url="http://127.0.0.1:11434",
            profile_name="elite",
        )

    def test_call_ollama_retries_on_http_524_then_succeeds(self):
        engine = self._build_engine(
            budget_plan={
                "retries": 2,
                "retry_backoff_factor": 1.0,
                "retry_jitter_s": 0.0,
                "retryable_status_codes": [524, 502, 503],
                "connect_timeout_s": 4,
                "read_timeout_s": 30,
                "timeout_s": 30,
                "max_context_tokens": 8192,
                "max_output_tokens": 256,
                "temperature": 0.0,
                "top_p": 0.7,
            }
        )

        responses = [
            FakeHTTPResponse(524, {}),
            FakeHTTPResponse(200, {"response": "[]"}),
        ]

        with patch.object(backend_module.requests, "post", side_effect=responses) as mocked_post, \
             patch.object(backend_module, "save_raw_response", return_value=None), \
             patch.object(backend_module.time, "sleep", return_value=None), \
             patch.object(backend_module.random, "uniform", return_value=0.0):
            result = engine.call_ollama(prompt="{}", filename="service.py")

        self.assertIsNotNone(result)
        self.assertEqual(result["data"], [])
        self.assertEqual(mocked_post.call_count, 2)

    def test_call_ollama_uses_distinct_connect_and_read_timeouts(self):
        engine = self._build_engine(
            budget_plan={
                "retries": 1,
                "connect_timeout_s": 5,
                "read_timeout_s": 77,
                "timeout_s": 77,
                "max_context_tokens": 8192,
                "max_output_tokens": 256,
                "temperature": 0.0,
                "top_p": 0.7,
            }
        )

        captured_timeouts = []

        def fake_post(*args, **kwargs):
            captured_timeouts.append(kwargs.get("timeout"))
            return FakeHTTPResponse(200, {"response": "[]"})

        with patch.object(backend_module.requests, "post", side_effect=fake_post), \
             patch.object(backend_module, "save_raw_response", return_value=None):
            result = engine.call_ollama(prompt="{}", filename="worker.py")

        self.assertIsNotNone(result)
        self.assertEqual(captured_timeouts, [(5, 77)])


if __name__ == "__main__":
    unittest.main()
