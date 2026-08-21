import json
import os
import unittest

from backend.analysis_context import (
    AnalysisUnitBuilder,
    ContextPackBuilder,
    ReachabilityAnalyzer,
)
from backend.project_graph import (
    EDGE_CALLS,
    EDGE_EXPOSES,
    ProjectGraphBuilder,
    classify_file,
)


FIXTURE_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "project_graph_python")
)


class ProjectGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = ProjectGraphBuilder(FIXTURE_ROOT).build()
        cls.reachability = ReachabilityAnalyzer().analyze(cls.graph)
        cls.units = AnalysisUnitBuilder().build(cls.graph, cls.reachability)

    def _node(self, name):
        return next(node for node in self.graph.nodes.values() if node.name == name)

    def _unit(self, entrypoint):
        return next(unit for unit in self.units if unit.entrypoint == entrypoint)

    def test_file_classification(self):
        self.assertEqual(classify_file("app/routes.py"), "runtime")
        self.assertEqual(classify_file("tests/test_command.py"), "test")
        self.assertEqual(classify_file("examples/demo.py"), "example")
        self.assertEqual(classify_file("vendor/pkg.py"), "vendor")
        self.assertEqual(classify_file("generated/client.py"), "generated")
        self.assertEqual(classify_file("pyproject.toml"), "config")

    def test_serialization_and_edge_provenance(self):
        payload = json.loads(self.graph.to_json())
        self.assertGreater(len(payload["nodes"]), 10)
        self.assertGreater(len(payload["edges"]), 10)
        call = next(edge for edge in payload["edges"] if edge["type"] == EDGE_CALLS)
        self.assertTrue(call["evidence"]["path"])
        self.assertIsInstance(call["evidence"]["line_start"], int)
        self.assertEqual(call["evidence"]["extractor"], "python_ast")
        self.assertGreater(call["evidence"]["confidence"], 0)

    def test_fastapi_and_pyproject_entrypoints(self):
        entrypoints = [node for node in self.graph.nodes.values() if node.kind == "entrypoint"]
        names = {node.name for node in entrypoints}
        self.assertIn("POST /run", names)
        self.assertIn("POST /safe-run", names)
        self.assertIn("CLI nexus-fixture", names)
        route = next(node for node in entrypoints if node.name == "POST /run")
        exposes = self.graph.outgoing(route.id, {EDGE_EXPOSES})
        self.assertEqual(self.graph.nodes[exposes[0].target].name, "app.routes.run_command")

    def test_confirmed_inter_file_call_path(self):
        unit = self._unit("POST /run")
        self.assertEqual(unit.reachability, "confirmed")
        self.assertEqual(
            unit.call_path[:3],
            ["app.routes.run_command", "app.services.execute_command", "app.repository.run_command"],
        )
        self.assertIn("os.system", json.dumps(unit.potential_sinks))
        self.assertEqual(
            self.reachability[self._node("app.repository.run_command").id].status,
            "confirmed",
        )

    def test_dead_code_is_unreachable(self):
        dead = self._node("app.dead_code.never_called")
        self.assertEqual(self.reachability[dead.id].status, "unreachable")

    def test_test_pattern_is_test_only(self):
        test_symbol = self._node("tests.test_command.test_dangerous_pattern_only_in_test")
        self.assertEqual(self.reachability[test_symbol.id].status, "test_only")
        test_unit = self._unit("test tests.test_command.test_dangerous_pattern_only_in_test")
        self.assertEqual(test_unit.reachability, "test_only")

    def test_sanitizer_and_shell_control_are_visible(self):
        unit = self._unit("POST /safe-run")
        controls = json.dumps(unit.known_controls)
        self.assertIn("shell argument quoting", controls)
        self.assertIn("subprocess shell disabled", controls)

    def test_import_cycle_does_not_loop(self):
        first = self._node("app.cycle_a.first")
        second = self._node("app.cycle_b.second")
        self.assertTrue(any(edge.target == second.id for edge in self.graph.outgoing(first.id, {EDGE_CALLS})))
        self.assertTrue(any(edge.target == first.id for edge in self.graph.outgoing(second.id, {EDGE_CALLS})))
        self.assertLess(len(self.graph.nodes), 100)

    def test_dynamic_call_stays_unknown_not_unreachable(self):
        unit = self._unit("POST /dispatch/{handler}")
        self.assertEqual(unit.reachability, "unknown")
        dynamic_nodes = [
            node for node in self.graph.nodes.values()
            if node.kind == "external_dependency" and node.attributes.get("dependency_type") == "dynamic_call"
        ]
        self.assertTrue(dynamic_nodes)
        reached_dynamic = [self.reachability[node.id].status for node in dynamic_nodes]
        self.assertIn("unknown", reached_dynamic)
        self.assertNotIn("unreachable", reached_dynamic)
        self.assertTrue(unit.uncertainties)

    def test_context_pack_contains_required_sections_and_lines(self):
        unit = self._unit("POST /run")
        pack = ContextPackBuilder().build(unit)
        for section in (
            "COMPONENT / ANALYSIS UNIT",
            "ENTRYPOINT",
            "REACHABILITY STATUS",
            "CALL PATH",
            "FILES INVOLVED",
            "RELEVANT CODE SNIPPETS",
            "KNOWN CONTROLS",
            "POTENTIAL SOURCES",
            "POTENTIAL SINKS",
            "UNCERTAINTIES",
            "GRAPH CONFIDENCE",
        ):
            self.assertIn(section, pack.text)
        self.assertIn("app/routes.py:", pack.text)
        self.assertIn("app/repository.py:", pack.text)

if __name__ == "__main__":
    unittest.main()
