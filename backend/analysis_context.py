"""Reachability, analysis-unit, and model-context construction for ProjectGraph."""

from __future__ import annotations

import hashlib
import os
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from .project_graph import (
        EDGE_CALLS,
        EDGE_EXPOSES,
        GraphEdge,
        ProjectGraph,
        classify_file,
    )
except ImportError:  # pragma: no cover - direct backend execution compatibility
    from project_graph import EDGE_CALLS, EDGE_EXPOSES, GraphEdge, ProjectGraph, classify_file


REACHABILITY_CONFIRMED = "confirmed"
REACHABILITY_LIKELY = "likely"
REACHABILITY_UNKNOWN = "unknown"
REACHABILITY_UNREACHABLE = "unreachable"
REACHABILITY_TEST_ONLY = "test_only"
REACHABILITY_NOT_APPLICABLE = "not_applicable"

REACHABILITY_VALUES = {
    REACHABILITY_CONFIRMED,
    REACHABILITY_LIKELY,
    REACHABILITY_UNKNOWN,
    REACHABILITY_UNREACHABLE,
    REACHABILITY_TEST_ONLY,
    REACHABILITY_NOT_APPLICABLE,
}


@dataclass
class ReachabilityResult:
    node_id: str
    status: str
    path: List[str] = field(default_factory=list)
    edge_evidence: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    root_entrypoint_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReachabilityAnalyzer:
    """Conservative traversal over EXPOSES/CALLS edges.

    IMPORTS is intentionally not treated as a call path.  Unknown edges propagate
    ``unknown`` to their unresolved target and scoped candidate symbols, never
    ``unreachable``.
    """

    _STATUS_PRIORITY = {
        REACHABILITY_CONFIRMED: 3,
        REACHABILITY_LIKELY: 2,
        REACHABILITY_UNKNOWN: 1,
    }

    def analyze(self, graph: ProjectGraph) -> Dict[str, ReachabilityResult]:
        runtime_roots = [
            node.id for node in graph.nodes.values()
            if node.kind == "entrypoint" and node.attributes.get("root_scope", "runtime") != "test"
        ]
        test_roots = [
            node.id for node in graph.nodes.values()
            if node.kind == "entrypoint" and node.attributes.get("root_scope") == "test"
        ]

        runtime = self._walk(graph, runtime_roots)
        tests = self._walk(graph, test_roots)
        results: Dict[str, ReachabilityResult] = {}

        for node_id, node in graph.nodes.items():
            if node_id in runtime:
                result = runtime[node_id]
            elif node_id in tests:
                test_result = tests[node_id]
                result = ReachabilityResult(
                    node_id=node_id,
                    status=REACHABILITY_TEST_ONLY,
                    path=test_result.path,
                    edge_evidence=test_result.edge_evidence,
                    reason="reachable_only_from_test_entrypoint",
                    root_entrypoint_id=test_result.root_entrypoint_id,
                )
            else:
                result = self._default_result(graph, node_id)
            results[node_id] = result

        # File reachability is the strongest reachability of a contained symbol;
        # CONTAINS itself is not an execution edge and is therefore aggregated only
        # after the call-path traversal.
        for node_id, node in graph.nodes.items():
            if node.kind != "file" or not node.path:
                continue
            contained = [
                result for symbol_id, result in results.items()
                if symbol_id != node_id
                and graph.nodes[symbol_id].kind == "symbol"
                and graph.nodes[symbol_id].path == node.path
            ]
            if not contained:
                continue
            runtime_candidates = [
                result for result in contained
                if result.status in {REACHABILITY_CONFIRMED, REACHABILITY_LIKELY, REACHABILITY_UNKNOWN}
            ]
            if runtime_candidates:
                best = max(runtime_candidates, key=lambda result: self._STATUS_PRIORITY.get(result.status, 0))
                results[node_id] = ReachabilityResult(
                    node_id=node_id,
                    status=best.status,
                    path=best.path,
                    edge_evidence=best.edge_evidence,
                    reason="contains_runtime_reachable_symbol",
                    root_entrypoint_id=best.root_entrypoint_id,
                )
            elif all(result.status == REACHABILITY_TEST_ONLY for result in contained):
                results[node_id] = ReachabilityResult(
                    node_id=node_id,
                    status=REACHABILITY_TEST_ONLY,
                    reason="contains_only_test_symbols",
                )

        for node_id, result in results.items():
            graph.nodes[node_id].attributes["reachability"] = result.to_dict()

        graph.metadata["reachability"] = {
            "states": sorted(REACHABILITY_VALUES),
            "counts": {
                status: sum(1 for result in results.values() if result.status == status)
                for status in sorted(REACHABILITY_VALUES)
            },
            "runtime_roots": runtime_roots,
            "test_roots": test_roots,
        }
        return results

    def _walk(self, graph: ProjectGraph, roots: Sequence[str]) -> Dict[str, ReachabilityResult]:
        results: Dict[str, ReachabilityResult] = {}
        queue = deque()
        for root_id in roots:
            result = ReachabilityResult(
                node_id=root_id,
                status=REACHABILITY_CONFIRMED,
                path=[root_id],
                reason="runtime_entrypoint" if graph.nodes[root_id].attributes.get("root_scope") != "test" else "test_entrypoint",
                root_entrypoint_id=root_id,
            )
            results[root_id] = result
            queue.append(result)

        while queue:
            current = queue.popleft()
            for edge in graph.outgoing(current.node_id, {EDGE_EXPOSES, EDGE_CALLS}):
                next_status = self._transition(current.status, edge)
                candidate = ReachabilityResult(
                    node_id=edge.target,
                    status=next_status,
                    path=current.path + [edge.target],
                    edge_evidence=current.edge_evidence + [edge.to_dict()],
                    reason=self._edge_reason(edge, next_status),
                    root_entrypoint_id=current.root_entrypoint_id,
                )
                existing = results.get(edge.target)
                if existing is None or self._is_better(candidate, existing):
                    results[edge.target] = candidate
                    queue.append(candidate)

                if next_status == REACHABILITY_UNKNOWN:
                    for symbol_id in edge.attributes.get("candidate_symbol_ids", []):
                        if symbol_id not in graph.nodes:
                            continue
                        scoped = ReachabilityResult(
                            node_id=symbol_id,
                            status=REACHABILITY_UNKNOWN,
                            path=current.path + [edge.target, symbol_id],
                            edge_evidence=current.edge_evidence + [edge.to_dict()],
                            reason="possible_target_of_dynamic_call",
                            root_entrypoint_id=current.root_entrypoint_id,
                        )
                        scoped_existing = results.get(symbol_id)
                        if scoped_existing is None or self._is_better(scoped, scoped_existing):
                            results[symbol_id] = scoped
                            queue.append(scoped)
        return results

    def _transition(self, current: str, edge: GraphEdge) -> str:
        if current == REACHABILITY_UNKNOWN or edge.attributes.get("resolution") == "unknown" or edge.evidence.uncertainty_reason:
            return REACHABILITY_UNKNOWN
        confidence = float(edge.evidence.confidence)
        if current == REACHABILITY_LIKELY or confidence < 0.9:
            return REACHABILITY_LIKELY
        return REACHABILITY_CONFIRMED

    def _edge_reason(self, edge: GraphEdge, status: str) -> str:
        if status == REACHABILITY_UNKNOWN:
            return edge.evidence.uncertainty_reason or "edge_resolution_unknown"
        if status == REACHABILITY_LIKELY:
            return f"inferred_path_confidence_{edge.evidence.confidence:.2f}"
        return "deterministic_entrypoint_call_path"

    def _is_better(self, candidate: ReachabilityResult, current: ReachabilityResult) -> bool:
        candidate_priority = self._STATUS_PRIORITY.get(candidate.status, 0)
        current_priority = self._STATUS_PRIORITY.get(current.status, 0)
        if candidate_priority != current_priority:
            return candidate_priority > current_priority
        return len(candidate.path) < len(current.path)

    def _default_result(self, graph: ProjectGraph, node_id: str) -> ReachabilityResult:
        node = graph.nodes[node_id]
        if node.kind == "external_dependency":
            if node.attributes.get("resolution") == "unknown":
                return ReachabilityResult(node_id, REACHABILITY_UNKNOWN, reason="unresolved_external_or_dynamic_target")
            return ReachabilityResult(node_id, REACHABILITY_NOT_APPLICABLE, reason="external_dependency_without_call_path")
        if node.kind == "entrypoint":
            if node.attributes.get("resolution") == "unknown":
                return ReachabilityResult(node_id, REACHABILITY_UNKNOWN, path=[node_id], reason="entrypoint_target_unresolved")
            return ReachabilityResult(node_id, REACHABILITY_UNREACHABLE, reason="entrypoint_not_connected_to_symbol")
        classification = node.attributes.get("classification") or node.attributes.get("file_classification")
        if classification == "test":
            return ReachabilityResult(node_id, REACHABILITY_TEST_ONLY, reason="classified_as_test_without_runtime_path")
        if classification == "config":
            return ReachabilityResult(node_id, REACHABILITY_NOT_APPLICABLE, reason="configuration_file")
        if classification == "unknown":
            return ReachabilityResult(node_id, REACHABILITY_UNKNOWN, reason="file_role_unknown")
        return ReachabilityResult(node_id, REACHABILITY_UNREACHABLE, reason="no_path_from_runtime_entrypoint")


@dataclass
class AnalysisUnit:
    id: str
    entrypoint_id: str
    entrypoint: str
    entrypoint_type: str
    reachability: str
    call_path: List[str]
    call_path_node_ids: List[str]
    symbols: List[str]
    symbol_ids: List[str]
    files: List[Dict[str, Any]]
    snippets: List[Dict[str, Any]]
    potential_sources: List[Any]
    potential_sinks: List[Any]
    known_controls: List[Any]
    uncertainties: List[str]
    graph_confidence: float
    project_root: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AnalysisUnitBuilder:
    def __init__(self, max_symbols: int = 32, max_depth: int = 12, snippet_line_limit: int = 120):
        self.max_symbols = max(1, int(max_symbols))
        self.max_depth = max(1, int(max_depth))
        self.snippet_line_limit = max(8, int(snippet_line_limit))

    def build(
        self,
        graph: ProjectGraph,
        reachability: Optional[Dict[str, ReachabilityResult]] = None,
    ) -> List[AnalysisUnit]:
        reachability = reachability or ReachabilityAnalyzer().analyze(graph)
        units: List[AnalysisUnit] = []
        entrypoints = sorted(
            (node for node in graph.nodes.values() if node.kind == "entrypoint"),
            key=lambda node: (node.path or "", node.line_start or 0, node.name),
        )
        for entrypoint in entrypoints:
            unit = self._build_for_entrypoint(graph, entrypoint.id, reachability)
            if unit is not None:
                units.append(unit)
        return units

    def _build_for_entrypoint(
        self,
        graph: ProjectGraph,
        entrypoint_id: str,
        reachability: Dict[str, ReachabilityResult],
    ) -> Optional[AnalysisUnit]:
        entrypoint = graph.nodes[entrypoint_id]
        queue = deque([(entrypoint_id, [entrypoint_id], [])])
        best_paths: Dict[str, Tuple[List[str], List[GraphEdge]]] = {entrypoint_id: ([entrypoint_id], [])}
        ordered_ids: List[str] = []
        traversed_edges: List[GraphEdge] = []
        dynamic_unknown = False

        while queue:
            node_id, path, path_edges = queue.popleft()
            if len(path) > self.max_depth + 1:
                continue
            for edge in graph.outgoing(node_id, {EDGE_EXPOSES, EDGE_CALLS}):
                if edge in traversed_edges:
                    continue
                traversed_edges.append(edge)
                if edge.attributes.get("resolution") == "unknown" or edge.evidence.uncertainty_reason:
                    dynamic_unknown = True
                target_path = path + [edge.target]
                target_edges = path_edges + [edge]
                existing = best_paths.get(edge.target)
                if existing is None or len(target_path) < len(existing[0]):
                    best_paths[edge.target] = (target_path, target_edges)
                    queue.append((edge.target, target_path, target_edges))
                node = graph.nodes.get(edge.target)
                if node and node.kind == "symbol" and edge.target not in ordered_ids:
                    ordered_ids.append(edge.target)
                    if len(ordered_ids) >= self.max_symbols:
                        queue.clear()
                        break

        if not ordered_ids:
            return None

        primary_target = self._select_primary_target(graph, ordered_ids, best_paths)
        primary_path_ids, primary_edges = best_paths[primary_target]
        display_path_ids = [node_id for node_id in primary_path_ids if graph.nodes[node_id].kind != "entrypoint"]
        call_path = [graph.nodes[node_id].name for node_id in display_path_ids]
        symbols = [graph.nodes[node_id].name for node_id in ordered_ids]
        snippets = self._build_snippets(graph, ordered_ids)
        files = self._build_file_ranges(snippets)
        sources, sinks, controls, uncertainties = self._collect_annotations(graph, ordered_ids, traversed_edges)
        confidence_edges = primary_edges or traversed_edges
        graph_confidence = round(
            (
                sum(edge.evidence.confidence for edge in confidence_edges) / len(confidence_edges)
                if confidence_edges
                else float(entrypoint.attributes.get("confidence", 0.0))
            ),
            3,
        )

        root_scope = entrypoint.attributes.get("root_scope", "runtime")
        if root_scope == "test":
            status = REACHABILITY_TEST_ONLY
        elif dynamic_unknown:
            status = REACHABILITY_UNKNOWN
        else:
            target_reachability = reachability.get(primary_target)
            status = target_reachability.status if target_reachability else REACHABILITY_UNKNOWN
        if status not in REACHABILITY_VALUES:
            status = REACHABILITY_UNKNOWN

        digest = hashlib.sha1(
            f"{entrypoint_id}:{'|'.join(ordered_ids)}".encode("utf-8")
        ).hexdigest()[:12]
        return AnalysisUnit(
            id=f"analysis-unit:{digest}",
            entrypoint_id=entrypoint_id,
            entrypoint=entrypoint.name,
            entrypoint_type=str(entrypoint.attributes.get("entrypoint_type", "unknown")),
            reachability=status,
            call_path=call_path,
            call_path_node_ids=display_path_ids,
            symbols=symbols,
            symbol_ids=ordered_ids,
            files=files,
            snippets=snippets,
            potential_sources=sources,
            potential_sinks=sinks,
            known_controls=controls,
            uncertainties=uncertainties,
            graph_confidence=graph_confidence,
            project_root=graph.root,
        )

    def _select_primary_target(
        self,
        graph: ProjectGraph,
        symbol_ids: Sequence[str],
        paths: Dict[str, Tuple[List[str], List[GraphEdge]]],
    ) -> str:
        def score(node_id: str) -> Tuple[int, int, str]:
            node = graph.nodes[node_id]
            has_sink = 1 if node.attributes.get("sinks") else 0
            return has_sink, len(paths[node_id][0]), node.name
        return max(symbol_ids, key=score)

    def _build_snippets(self, graph: ProjectGraph, symbol_ids: Sequence[str]) -> List[Dict[str, Any]]:
        snippets: List[Dict[str, Any]] = []
        seen = set()
        for symbol_id in symbol_ids:
            node = graph.nodes[symbol_id]
            if not node.path or node.line_start is None:
                continue
            key = (node.path, node.line_start, node.line_end)
            if key in seen:
                continue
            seen.add(key)
            absolute = os.path.join(graph.root, node.path)
            try:
                with open(absolute, "r", encoding="utf-8", errors="ignore") as handle:
                    lines = handle.readlines()
            except OSError:
                continue
            start = max(1, int(node.line_start))
            requested_end = int(node.line_end or start)
            end = min(len(lines), requested_end, start + self.snippet_line_limit - 1)
            content = "".join(lines[start - 1:end]).rstrip()
            snippets.append({
                "symbol": node.name,
                "path": node.path,
                "line_start": start,
                "line_end": end,
                "code": content,
            })
        return snippets

    def _build_file_ranges(self, snippets: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ranges: Dict[str, List[int]] = {}
        for snippet in snippets:
            path = snippet["path"]
            start, end = int(snippet["line_start"]), int(snippet["line_end"])
            if path not in ranges:
                ranges[path] = [start, end]
            else:
                ranges[path][0] = min(ranges[path][0], start)
                ranges[path][1] = max(ranges[path][1], end)
        return [
            {"path": path, "line_start": span[0], "line_end": span[1], "classification": classify_file(path)}
            for path, span in sorted(ranges.items())
        ]

    def _collect_annotations(
        self,
        graph: ProjectGraph,
        symbol_ids: Sequence[str],
        edges: Sequence[GraphEdge],
    ) -> Tuple[List[Any], List[Any], List[Any], List[str]]:
        sources: List[Any] = []
        sinks: List[Any] = []
        controls: List[Any] = []
        uncertainties: List[str] = []
        for symbol_id in symbol_ids:
            node = graph.nodes[symbol_id]
            for target, key in ((sources, "sources"), (sinks, "sinks"), (controls, "controls")):
                for item in node.attributes.get(key, []):
                    enriched = {"symbol": node.name, **item} if isinstance(item, dict) else f"{node.name}: {item}"
                    if enriched not in target:
                        target.append(enriched)
            for uncertainty in node.attributes.get("uncertainties", []):
                if uncertainty not in uncertainties:
                    uncertainties.append(uncertainty)
        for edge in edges:
            if edge.evidence.uncertainty_reason:
                message = (
                    f"{edge.evidence.path}:{edge.evidence.line_start or '?'} "
                    f"{edge.evidence.uncertainty_reason}"
                )
                if message not in uncertainties:
                    uncertainties.append(message)
        return sources, sinks, controls, uncertainties


@dataclass
class ContextPack:
    analysis_unit_id: str
    text: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContextPackBuilder:
    """Render a bounded, line-addressable inter-file security context."""

    def __init__(self, max_chars: int = 48000):
        self.max_chars = max(4000, int(max_chars))

    def build(self, unit: AnalysisUnit) -> ContextPack:
        sections = [
            "COMPONENT / ANALYSIS UNIT\n" + unit.id,
            "ENTRYPOINT\n" + unit.entrypoint,
            "REACHABILITY STATUS\n" + unit.reachability,
            "CALL PATH\n" + ("\n→ ".join(unit.call_path) if unit.call_path else "unknown"),
            "FILES INVOLVED\n" + self._format_files(unit.files),
            "RELEVANT CODE SNIPPETS\n" + self._format_snippets(unit.snippets),
            "KNOWN CONTROLS\n" + self._format_items(unit.known_controls),
            "POTENTIAL SOURCES\n" + self._format_items(unit.potential_sources),
            "POTENTIAL SINKS\n" + self._format_items(unit.potential_sinks),
            "UNCERTAINTIES\n" + self._format_items(unit.uncertainties),
            f"GRAPH CONFIDENCE\n{unit.graph_confidence:.3f}",
        ]
        text = "\n\n".join(sections)
        if len(text) > self.max_chars:
            suffix = "\n\n[Context pack truncated to configured character budget]"
            text = text[: self.max_chars - len(suffix)].rstrip() + suffix
        return ContextPack(
            analysis_unit_id=unit.id,
            text=text,
            metadata={
                "entrypoint": unit.entrypoint,
                "entrypoint_type": unit.entrypoint_type,
                "reachability": unit.reachability,
                "call_path": list(unit.call_path),
                "graph_confidence": unit.graph_confidence,
                "files": [item["path"] for item in unit.files],
                "project_root": unit.project_root,
            },
        )

    def _format_files(self, files: Sequence[Dict[str, Any]]) -> str:
        if not files:
            return "none"
        return "\n".join(
            f"- {item['path']}:{item['line_start']}-{item['line_end']} [{item.get('classification', 'unknown')}]"
            for item in files
        )

    def _format_snippets(self, snippets: Sequence[Dict[str, Any]]) -> str:
        if not snippets:
            return "none"
        rendered = []
        for snippet in snippets:
            rendered.append(
                f"FILE {snippet['path']}:{snippet['line_start']}-{snippet['line_end']}\n"
                f"SYMBOL {snippet['symbol']}\n"
                f"```\n{snippet['code']}\n```"
            )
        return "\n\n".join(rendered)

    def _format_items(self, items: Iterable[Any]) -> str:
        items = list(items)
        if not items:
            return "none observed"
        lines = []
        for item in items:
            if isinstance(item, dict):
                ordered = ", ".join(f"{key}={value}" for key, value in item.items())
                lines.append(f"- {ordered}")
            else:
                lines.append(f"- {item}")
        return "\n".join(lines)
