import asyncio
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


class ReportHtmlEscapeTests(unittest.TestCase):
    def setUp(self):
        self._saved_scan_state = copy.deepcopy(backend_module.scan_state)

    def tearDown(self):
        backend_module.scan_state.clear()
        backend_module.scan_state.update(copy.deepcopy(self._saved_scan_state))

    def test_export_report_html_escapes_untrusted_fields(self):
        backend_module.scan_state["id"] = "scan-<script>alert(1)</script>"
        backend_module.scan_state["profile"] = "elite"
        backend_module.scan_state["mode"] = "deep"
        backend_module.scan_state["stats"] = {"critical": 0, "high": 1, "medium": 0, "low": 0, "files": 1, "skipped": 0}
        backend_module.scan_state["confidence_score"] = 99.5
        backend_module.scan_state["vulnerabilities"] = [
            {
                "severity": "High",
                "title": "<img src=x onerror=alert(1)>",
                "confidence": 90,
                "file": "src/<script>.py",
                "line": "<b>7</b>",
                "description": "<script>alert('xss')</script>",
                "snippet": "dangerous('<tag>')",
                "fix": "escape('<tag>')",
            }
        ]

        class DummyHtmlResponse:
            def __init__(self, content):
                self.content = content

        with patch.object(backend_module, "HTMLResponse", DummyHtmlResponse):
            response = asyncio.run(backend_module.export_report_html())

        content = response.content
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", content)
        self.assertIn("src/&lt;script&gt;.py", content)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", content)
        self.assertIn("dangerous(&#x27;&lt;tag&gt;&#x27;)", content)
        self.assertIn("escape(&#x27;&lt;tag&gt;&#x27;)", content)
        self.assertNotIn("<img src=x onerror=alert(1)>", content)
        self.assertNotIn("<script>alert('xss')</script>", content)


if __name__ == "__main__":
    unittest.main()
