import os
import sys
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


FIXTURES_ROOT = "/Users/pacome/nexus_auditor/fixtures/evidence"


class LineResolutionTests(unittest.TestCase):
    def test_normalize_vulnerability_resolves_line_from_exact_snippet(self):
        filepath = os.path.join(FIXTURES_ROOT, "pickle_usage.py")
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        normalized = backend_module.normalize_vulnerability(
            vuln={
                "title": "Unsafe pickle deserialization",
                "type": "DESERIALIZATION",
                "severity": "High",
                "evidence": "pickle.loads(payload)",
                "description": "Untrusted bytes are passed to pickle.loads",
                "fix": "Use a safe parser",
                "confidence": 95,
            },
            filepath=filepath,
            filename="pickle_usage.py",
            raw_response="[]",
            file_content=content,
        )

        self.assertIsInstance(normalized.get("line"), int)
        self.assertGreater(normalized.get("line"), 0)
        self.assertEqual(normalized.get("line_reason"), "exact_line_match")

    def test_normalize_vulnerability_sets_na_when_snippet_not_found(self):
        filepath = os.path.join(FIXTURES_ROOT, "pickle_usage.py")
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        normalized = backend_module.normalize_vulnerability(
            vuln={
                "title": "Fake finding",
                "type": "DESERIALIZATION",
                "severity": "High",
                "evidence": "this_snippet_does_not_exist_anywhere()",
                "description": "No local proof",
                "fix": "N/A",
                "confidence": 90,
            },
            filepath=filepath,
            filename="pickle_usage.py",
            raw_response="[]",
            file_content=content,
        )

        self.assertEqual(normalized.get("line"), "N/A")
        self.assertEqual(normalized.get("line_end"), "N/A")
        self.assertIn(normalized.get("line_reason"), {"snippet_not_found", "snippet_too_short_for_fuzzy"})


if __name__ == "__main__":
    unittest.main()
