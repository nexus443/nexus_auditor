import os
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


class EvidenceGateTests(unittest.TestCase):
    def test_js_fixture_without_pickle_drops_deserialization_hallucination(self):
        filepath = os.path.join(FIXTURES_ROOT, "App.jsx")
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        fake_finding = {
            "file": "App.jsx",
            "filepath": filepath,
            "title": "Insecure deserialization via pickle",
            "type": "DESERIALIZATION",
            "severity": "High",
            "line": 3,
            "line_end": 3,
            "evidence": "pickle.loads(payload)",
            "description": "Cross-file hint: maybe pickle in UI layer",
            "fix": "Do not deserialize untrusted data",
            "confidence": 92,
            "snippet": "pickle.loads(payload)",
        }

        with patch.object(backend_module, "STRICT_EVIDENCE", True):
            filtered = backend_module.apply_mode_filters([fake_finding], backend_module.SCAN_MODES["deep"], filepath, content)

        self.assertEqual(filtered, [])

    def test_pickle_fixture_accepts_verified_deserialization_with_line(self):
        filepath = os.path.join(FIXTURES_ROOT, "pickle_usage.py")
        filename = os.path.basename(filepath)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        llm_output = {
            "title": "Unsafe pickle deserialization",
            "type": "DESERIALIZATION",
            "severity": "High",
            "evidence": "pickle.loads(payload)",
            "description": "Untrusted bytes are passed to pickle.loads",
            "fix": "Use a safe parser format",
            "confidence": 95,
        }

        normalized = backend_module.normalize_vulnerability(llm_output, filepath, filename, raw_response="[]", file_content=content)

        with patch.object(backend_module, "STRICT_EVIDENCE", True):
            filtered = backend_module.apply_mode_filters([normalized], backend_module.SCAN_MODES["deep"], filepath, content)

        self.assertEqual(len(filtered), 1)
        self.assertIsInstance(filtered[0].get("line"), int)
        self.assertGreater(filtered[0].get("line"), 0)
        self.assertIn("pickle.loads", filtered[0].get("evidence", ""))

    def test_cross_file_hint_cannot_create_vulnerability(self):
        filepath = os.path.join(FIXTURES_ROOT, "App.jsx")
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        cross_file_hint_only = {
            "file": "App.jsx",
            "filepath": filepath,
            "title": "Cross-file hint: possible deserialization issue",
            "type": "DESERIALIZATION",
            "severity": "High",
            "line": None,
            "line_end": None,
            "evidence": "",
            "description": "Cross-file hint from another file",
            "fix": "Inspect backend",
            "confidence": 80,
            "snippet": "",
        }

        with patch.object(backend_module, "STRICT_EVIDENCE", True):
            filtered = backend_module.apply_mode_filters([cross_file_hint_only], backend_module.SCAN_MODES["deep"], filepath, content)

        self.assertEqual(filtered, [])


if __name__ == "__main__":
    unittest.main()
