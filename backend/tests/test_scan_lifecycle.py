"""
Tests du cycle de vie canonique du scan :
idle | running | completed | failed | timeout | cancelled.

Règle centrale : `is_scanning == False` ne signifie JAMAIS « succès ».
Seul terminal_state == "completed" autorise résultats finaux, progress=100
et confiance numérique.
"""
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


def _finding(title="Lifecycle vuln", severity="Medium", confidence=70.0):
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": "demo",
        "file": "app.py",
    }


class ScanLifecycleTests(unittest.TestCase):
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

    @staticmethod
    def _collection_for_files(file_paths):
        total = sum(os.path.getsize(p) for p in file_paths)
        return {
            "file_entries": [{"path": p, "score": 0, "reasons": []} for p in file_paths],
            "files_discovered": len(file_paths),
            "files_scheduled": len(file_paths),
            "files_skipped": 0,
            "bytes_discovered": total,
            "bytes_scheduled": total,
            "excluded_policy_files": 0,
            "excluded_oversized_files": 0,
            "max_file_size_bytes": backend_module.get_max_scan_file_bytes(),
        }

    def _make_repo(self, repo_dir, count=2):
        paths = []
        for i in range(count):
            path = os.path.join(repo_dir, f"app_{i}.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"def run_{i}():\n    return {i}\n")
            paths.append(path)
        return paths

    # ------------------------------------------------------------------
    # Timeout global pendant analyze
    # ------------------------------------------------------------------
    def test_global_timeout_during_analyze_preserves_partial_findings(self):
        class FakeEngine:
            def __init__(self, *args, **kwargs):
                pass

            def scan_file(self, *args, **kwargs):
                return [_finding()]

        analyze_checks = {"count": 0}

        def deadline_side_effect(_deadline, context="scan"):
            # Laisse passer le 1er fichier, expire au 2e tour d'analyse.
            if context == "analyze":
                analyze_checks["count"] += 1
                if analyze_checks["count"] >= 2:
                    raise TimeoutError("Global scan timeout reached during analyze")

        with tempfile.TemporaryDirectory() as repo_dir:
            paths = self._make_repo(repo_dir, count=2)
            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "collect_scan_candidates", return_value=self._collection_for_files(paths)), \
                 patch.object(backend_module, "StableEngine", FakeEngine), \
                 patch.object(backend_module, "ensure_scan_within_deadline", side_effect=deadline_side_effect):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="eco",
                    mode_key="rapid",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_lc_timeout_analyze",
                )

        state = backend_module.scan_state
        report = state.get("stage_report", {})
        self.assertEqual(report.get("terminal_state"), "timeout")
        self.assertEqual(backend_module.compute_scan_lifecycle(state), "timeout")
        self.assertEqual(state.get("current_stage"), "timeout")
        self.assertFalse(state.get("is_scanning"))
        # Stages : normalize/index complétés, analyze interrompu, la suite skipped.
        self.assertEqual(report["stage_status"]["normalize"], "completed")
        self.assertEqual(report["stage_status"]["index"], "completed")
        self.assertEqual(report["stage_status"]["analyze"], "failed")
        self.assertEqual(report["stage_status"]["correlate"], "skipped")
        self.assertEqual(report["stage_status"]["report"], "skipped")
        self.assertEqual(report.get("interrupted_stage"), "analyze")
        # Progression figée sous 100, jamais terminée artificiellement.
        self.assertLess(int(state.get("progress") or 0), 100)
        self.assertGreater(int(state.get("progress") or 0), 0)
        # Détections partielles préservées, confiance non calculée, pas de rapport.
        self.assertEqual(len(state.get("vulnerabilities", [])), 1)
        self.assertIsNone(state.get("confidence_score"))
        self.assertFalse(state.get("report_generated"))

    # ------------------------------------------------------------------
    # Annulation utilisateur pendant analyze
    # ------------------------------------------------------------------
    def test_cancellation_during_analyze_keeps_progress_and_findings(self):
        class FakeEngine:
            def __init__(self, *args, **kwargs):
                pass

            def scan_file(self, *args, **kwargs):
                # Simule un « stop » utilisateur pendant le 1er fichier.
                backend_module.scan_state["should_stop"] = True
                return [_finding("Cancelled vuln")]

        with tempfile.TemporaryDirectory() as repo_dir:
            paths = self._make_repo(repo_dir, count=3)
            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "collect_scan_candidates", return_value=self._collection_for_files(paths)), \
                 patch.object(backend_module, "StableEngine", FakeEngine):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="balanced",
                    mode_key="deep",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_lc_cancel",
                )

        state = backend_module.scan_state
        report = state.get("stage_report", {})
        self.assertEqual(report.get("terminal_state"), "stopped")
        self.assertEqual(backend_module.compute_scan_lifecycle(state), "cancelled")
        self.assertEqual(state.get("current_stage"), "stopped")
        self.assertEqual(report["stage_status"]["analyze"], "cancelled")
        self.assertEqual(report["stage_status"]["correlate"], "skipped")
        self.assertEqual(report["stage_status"]["report"], "skipped")
        # Progression et détections partielles conservées.
        progress = int(state.get("progress") or 0)
        self.assertGreater(progress, 0)
        self.assertLess(progress, 100)
        self.assertEqual(len(state.get("vulnerabilities", [])), 1)
        self.assertIsNone(state.get("confidence_score"))
        self.assertFalse(state.get("report_generated"))

    # ------------------------------------------------------------------
    # Exception inattendue -> failed
    # ------------------------------------------------------------------
    def test_unexpected_exception_is_failed_not_completed(self):
        with tempfile.TemporaryDirectory() as repo_dir:
            self._make_repo(repo_dir, count=1)
            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "collect_scan_candidates", side_effect=RuntimeError("boom lifecycle")):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="balanced",
                    mode_key="deep",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_lc_failed",
                )

        state = backend_module.scan_state
        self.assertEqual(state.get("stage_report", {}).get("terminal_state"), "failed")
        self.assertEqual(backend_module.compute_scan_lifecycle(state), "failed")
        self.assertLess(int(state.get("progress") or 0), 100)
        self.assertIsNone(state.get("confidence_score"))
        self.assertFalse(state.get("report_generated"))

    # ------------------------------------------------------------------
    # Corrélation OK mais échec du stage report
    # ------------------------------------------------------------------
    def test_report_failure_after_successful_correlation(self):
        class FakeEngine:
            def __init__(self, *args, **kwargs):
                pass

            def scan_file(self, *args, **kwargs):
                return [_finding("Report-failure vuln", confidence=64.0)]

        with tempfile.TemporaryDirectory() as repo_dir:
            paths = self._make_repo(repo_dir, count=1)
            with patch.object(backend_module, "ensure_model_available", return_value=True), \
                 patch.object(backend_module, "collect_scan_candidates", return_value=self._collection_for_files(paths)), \
                 patch.object(backend_module, "StableEngine", FakeEngine), \
                 patch.object(backend_module, "correlate_findings", return_value=64.0), \
                 patch.object(backend_module, "save_to_history", side_effect=OSError("disk full")):
                backend_module.run_scan(
                    target=repo_dir,
                    profile_key="balanced",
                    mode_key="deep",
                    ollama_mode="auto",
                    ollama_url=None,
                    scan_id="scan_lc_report_fail",
                )

        state = backend_module.scan_state
        report = state.get("stage_report", {})
        self.assertEqual(report.get("terminal_state"), "failed")
        self.assertEqual(backend_module.compute_scan_lifecycle(state), "failed")
        self.assertEqual(report["stage_status"]["correlate"], "completed")
        self.assertEqual(report["stage_status"]["report"], "failed")
        # La corrélation a réellement abouti : la confiance calculée est conservée.
        self.assertEqual(state.get("confidence_score"), 64.0)
        # Mais le rapport n'a jamais été complété.
        self.assertFalse(state.get("report_generated"))
        self.assertLess(int(state.get("progress") or 0), 100)

    # ------------------------------------------------------------------
    # Endpoints : lifecycle exposé, jamais de succès implicite
    # ------------------------------------------------------------------
    def test_status_and_progress_payloads_expose_lifecycle(self):
        import asyncio

        backend_module.scan_state.update({
            "id": "scan_lc_payload",
            "is_scanning": False,
            "progress": 59,
            "current_stage": "timeout",
        })
        backend_module.scan_state["stage_report"] = backend_module.init_stage_report("analyze")
        backend_module.apply_terminal_to_stage_report(
            backend_module.scan_state["stage_report"], "timeout", interrupted_stage="analyze"
        )

        status_payload = asyncio.run(backend_module.get_status())
        self.assertEqual(status_payload.get("lifecycle"), "timeout")

        progress_payload = backend_module.build_scan_progress_snapshot()
        self.assertEqual(progress_payload.get("lifecycle"), "timeout")
        self.assertIsNone(progress_payload.get("confidence_score"))
        self.assertFalse(progress_payload.get("report_generated"))
        self.assertEqual(progress_payload.get("progress"), 59)

    def test_lifecycle_never_infers_success_from_not_scanning(self):
        # Scan interrompu sans terminal enregistré (ex: crash backend) :
        # jamais « completed ».
        state = backend_module.new_scan_state()
        state.update({"id": "scan_lc_crash", "is_scanning": False, "progress": 59})
        self.assertNotEqual(backend_module.compute_scan_lifecycle(state), "completed")

        # Aucun scan : idle.
        self.assertEqual(backend_module.compute_scan_lifecycle(backend_module.new_scan_state()), "idle")

        # En cours : running.
        running = backend_module.new_scan_state()
        running.update({"id": "x", "is_scanning": True})
        self.assertEqual(backend_module.compute_scan_lifecycle(running), "running")

    def test_double_terminal_application_keeps_interrupted_stage(self):
        # /scan/stop applique le terminal, puis le worker finalise à son tour :
        # le stage interrompu enregistré ne doit pas être perdu.
        report = backend_module.init_stage_report("analyze")
        backend_module.apply_terminal_to_stage_report(report, "stopped", interrupted_stage="analyze")
        self.assertEqual(report["interrupted_stage"], "analyze")
        backend_module.apply_terminal_to_stage_report(report, "stopped")
        self.assertEqual(report["interrupted_stage"], "analyze")
        self.assertEqual(report["stage_status"]["analyze"], "cancelled")

    def test_effective_confidence_hides_legacy_zero_without_correlation(self):
        # Ancien format : confidence_score initialisé à 0.0, corrélation jamais
        # aboutie → la confiance doit être « non calculée », pas 0 %.
        legacy = backend_module.new_scan_state()
        legacy.update({"id": "legacy", "confidence_score": 0.0})
        legacy["stage_report"] = backend_module.init_stage_report("analyze")
        legacy["stage_report"]["terminal_state"] = "failed"
        self.assertIsNone(backend_module.effective_confidence_score(legacy))

        # Scan complété avec zéro finding : 0.0 est un vrai score calculé.
        done = backend_module.new_scan_state()
        done.update({"id": "done", "confidence_score": 0.0})
        done["stage_report"] = backend_module.init_stage_report("report")
        backend_module.apply_terminal_to_stage_report(done["stage_report"], "completed")
        self.assertEqual(backend_module.effective_confidence_score(done), 0.0)

        # Corrélation aboutie puis échec du report : le score réel est conservé.
        partial = backend_module.new_scan_state()
        partial.update({"id": "partial", "confidence_score": 64.0})
        partial["stage_report"] = backend_module.init_stage_report("report")
        partial["stage_report"]["stage_status"]["correlate"] = "completed"
        partial["stage_report"]["terminal_state"] = "failed"
        self.assertEqual(backend_module.effective_confidence_score(partial), 64.0)

    def test_progress_is_monotonic_and_capped_below_100(self):
        backend_module.scan_state["progress"] = 0
        backend_module.set_scan_progress("analyze", 0.5)
        mid = backend_module.scan_state["progress"]
        self.assertGreater(mid, 10)
        self.assertLess(mid, 85)
        # Jamais en arrière.
        backend_module.set_scan_progress("analyze", 0.1)
        self.assertEqual(backend_module.scan_state["progress"], mid)
        # Jamais 100 hors finalize_success, même à 100 % du stage report.
        backend_module.set_scan_progress("report", 1.0)
        self.assertLessEqual(backend_module.scan_state["progress"], 99)


if __name__ == "__main__":
    unittest.main()
