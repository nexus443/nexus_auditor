"""Lightweight, evidence-backed project graph construction.

The V1 deliberately favours Python's standard-library AST over heuristic or LLM
resolution.  Every relation carries extraction evidence and unresolved dynamic
calls remain explicit graph nodes with ``resolution=unknown``.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - supported runtimes currently include it
    tomllib = None


EDGE_CONTAINS = "CONTAINS"
EDGE_IMPORTS = "IMPORTS"
EDGE_CALLS = "CALLS"
EDGE_EXPOSES = "EXPOSES"

SUPPORTED_EDGE_TYPES = {EDGE_CONTAINS, EDGE_IMPORTS, EDGE_CALLS, EDGE_EXPOSES}


@dataclass
class EdgeEvidence:
    path: str
    line_start: Optional[int]
    line_end: Optional[int]
    extractor: str
    confidence: float
    uncertainty_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    id: str
    name: str
    path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    kind: str = field(init=False, default="node")

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["kind"] = self.kind
        return payload


@dataclass
class FileNode(GraphNode):
    kind: str = field(init=False, default="file")


@dataclass
class SymbolNode(GraphNode):
    kind: str = field(init=False, default="symbol")


@dataclass
class EntrypointNode(GraphNode):
    kind: str = field(init=False, default="entrypoint")


@dataclass
class ExternalDependencyNode(GraphNode):
    kind: str = field(init=False, default="external_dependency")


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    evidence: EdgeEvidence
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.source,
            "to": self.target,
            "type": self.type,
            "evidence": self.evidence.to_dict(),
            "attributes": dict(self.attributes),
        }


@dataclass
class ProjectGraph:
    root: str
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    _edge_keys: set = field(default_factory=set, init=False, repr=False)

    def add_node(self, node: GraphNode) -> GraphNode:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if node.attributes:
            existing.attributes.update(node.attributes)
        return existing

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.type not in SUPPORTED_EDGE_TYPES:
            raise ValueError(f"Unsupported graph edge type: {edge.type}")
        key = (
            edge.source,
            edge.target,
            edge.type,
            edge.evidence.path,
            edge.evidence.line_start,
            edge.evidence.line_end,
        )
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(edge)

    def outgoing(self, node_id: str, edge_types: Optional[Iterable[str]] = None) -> List[GraphEdge]:
        allowed = set(edge_types) if edge_types is not None else None
        return [
            edge for edge in self.edges
            if edge.source == node_id and (allowed is None or edge.type in allowed)
        ]

    def incoming(self, node_id: str, edge_types: Optional[Iterable[str]] = None) -> List[GraphEdge]:
        allowed = set(edge_types) if edge_types is not None else None
        return [
            edge for edge in self.edges
            if edge.target == node_id and (allowed is None or edge.type in allowed)
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "nodes": [self.nodes[node_id].to_dict() for node_id in sorted(self.nodes)],
            "edges": [edge.to_dict() for edge in self.edges],
            "metadata": dict(self.metadata),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)


def normalize_relative_path(root: str, path: str) -> str:
    try:
        relative = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except (OSError, ValueError):
        relative = path
    return relative.replace(os.sep, "/")


CONFIG_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "pyproject.toml", "requirements.txt", "package.json", "package-lock.json", "Pipfile",
}
CONFIG_SUFFIXES = {".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf", ".env"}


def classify_file(path: str) -> str:
    """Classify without dropping files from the graph."""
    normalized = path.replace("\\", "/").strip("/")
    parts = [part.lower() for part in normalized.split("/") if part]
    name = parts[-1] if parts else normalized.lower()
    suffix = Path(name).suffix.lower()

    if any(part in {"node_modules", "vendor", "site-packages", ".venv", "venv"} for part in parts):
        return "vendor"
    if any(part in {"dist", "build", "generated", "__generated__"} for part in parts) or re.search(
        r"(?:\.generated\.|_generated\.|\.min\.(?:js|css)$)", name
    ):
        return "generated"
    if any(part in {"tests", "test", "spec", "specs"} for part in parts[:-1]) or re.match(
        r"(?:test_|.*_test\.|.*\.spec\.)", name
    ):
        return "test"
    if any(part in {"examples", "example", "samples", "sample", "fixtures"} for part in parts[:-1]):
        return "example"
    if name in {item.lower() for item in CONFIG_FILENAMES} or suffix in CONFIG_SUFFIXES:
        return "config"
    if suffix in {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".php", ".rb"}:
        return "runtime"
    return "unknown"


class SourceExtractor(Protocol):
    name: str

    def supports(self, path: str) -> bool:
        ...

    def index(self, builder: "ProjectGraphBuilder", path: str) -> None:
        ...


@dataclass
class _PythonIndex:
    path: str
    relative_path: str
    module: str
    is_package: bool
    tree: ast.AST
    content: str
    file_node_id: str
    module_symbol_id: str
    symbol_ids_by_ast: Dict[int, str] = field(default_factory=dict)
    symbol_ids_by_qualname: Dict[str, str] = field(default_factory=dict)
    imported_modules: Dict[str, str] = field(default_factory=dict)
    imported_symbols: Dict[str, Tuple[str, str]] = field(default_factory=dict)


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive for future AST shapes
        return node.__class__.__name__


def _expr_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expr_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    return None


def _literal_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _line_end(node: ast.AST) -> Optional[int]:
    return getattr(node, "end_lineno", getattr(node, "lineno", None))


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left = _literal_string(test.left) if isinstance(test.left, ast.Constant) else None
    right = _literal_string(test.comparators[0])
    left_name = test.left.id if isinstance(test.left, ast.Name) else None
    right_node = test.comparators[0]
    right_name = right_node.id if isinstance(right_node, ast.Name) else None
    return (left_name == "__name__" and right == "__main__") or (
        right_name == "__name__" and left == "__main__"
    )


SINK_SUFFIXES = {
    "os.system": "command_execution",
    "os.popen": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.run": "command_execution",
    "subprocess.Popen": "command_execution",
    "eval": "code_execution",
    "exec": "code_execution",
    "pickle.loads": "deserialization",
    "pickle.load": "deserialization",
    "yaml.load": "deserialization",
    "cursor.execute": "database_query",
    "execute": "database_query",
}

CONTROL_SUFFIXES = {
    "shlex.quote": "shell argument quoting",
    "html.escape": "HTML escaping",
    "markupsafe.escape": "HTML escaping",
    "bleach.clean": "HTML sanitization",
    "sanitize": "sanitization function",
    "sanitise": "sanitization function",
    "validate": "validation function",
}

DYNAMIC_CALL_NAMES = {"getattr", "setattr", "globals", "locals", "importlib.import_module", "__import__"}


class PythonAstExtractor:
    name = "python_ast"

    def supports(self, path: str) -> bool:
        return path.endswith((".py", ".pyw"))

    def index(self, builder: "ProjectGraphBuilder", path: str) -> None:
        builder._index_python_file(path)


class _DefinitionVisitor(ast.NodeVisitor):
    def __init__(self, builder: "ProjectGraphBuilder", index: _PythonIndex):
        self.builder = builder
        self.index = index
        self.scope: List[Tuple[str, str]] = []

    def _add_symbol(self, node: ast.AST, name: str, symbol_type: str) -> str:
        qual_parts = [scope_name for scope_name, _ in self.scope] + [name]
        qualname = ".".join(qual_parts)
        display_name = f"{self.index.module}.{qualname}" if self.index.module else qualname
        symbol_id = f"symbol:{display_name}"
        parent_id = self.scope[-1][1] if self.scope else self.index.file_node_id
        attributes = {
            "symbol_type": symbol_type,
            "qualname": qualname,
            "module": self.index.module,
            "file_classification": classify_file(self.index.relative_path),
            "sources": [],
            "sinks": [],
            "controls": [],
            "uncertainties": [],
        }
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            attributes["parameters"] = [arg.arg for arg in node.args.args]
        self.builder.graph.add_node(SymbolNode(
            id=symbol_id,
            name=display_name,
            path=self.index.relative_path,
            line_start=getattr(node, "lineno", None),
            line_end=_line_end(node),
            attributes=attributes,
        ))
        self.builder._add_edge(
            parent_id,
            symbol_id,
            EDGE_CONTAINS,
            self.index.relative_path,
            getattr(node, "lineno", None),
            _line_end(node),
            self.name,
            1.0,
        )
        self.index.symbol_ids_by_ast[id(node)] = symbol_id
        self.index.symbol_ids_by_qualname[qualname] = symbol_id
        self.builder.symbol_by_name[display_name] = symbol_id
        self.builder.symbols_by_module.setdefault(self.index.module, {})[qualname] = symbol_id
        return symbol_id

    @property
    def name(self) -> str:
        return "python_ast"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol_id = self._add_symbol(node, node.name, "class")
        self.scope.append((node.name, symbol_id))
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        symbol_type = "method" if self.scope and self.builder.graph.nodes[self.scope[-1][1]].attributes.get("symbol_type") == "class" else "function"
        symbol_id = self._add_symbol(node, node.name, symbol_type)
        self.scope.append((node.name, symbol_id))
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, builder: "ProjectGraphBuilder", index: _PythonIndex):
        self.builder = builder
        self.index = index
        self.symbol_stack: List[str] = [index.module_symbol_id]
        self.instance_types: List[Dict[str, str]] = [{}]

    @property
    def current_symbol_id(self) -> str:
        return self.symbol_stack[-1]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol_id = self.index.symbol_ids_by_ast.get(id(node))
        if symbol_id:
            self.symbol_stack.append(symbol_id)
            self.instance_types.append({})
            for statement in node.body:
                self.visit(statement)
            self.instance_types.pop()
            self.symbol_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        symbol_id = self.index.symbol_ids_by_ast.get(id(node))
        if not symbol_id:
            return
        self.symbol_stack.append(symbol_id)
        self.instance_types.append({})
        self._annotate_sources(node, symbol_id)
        for statement in node.body:
            self.visit(statement)
        self.instance_types.pop()
        self.symbol_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            constructor = self.builder._resolve_call_target(self.index, self.current_symbol_id, node.value.func, {})
            if constructor and constructor[0] in self.builder.graph.nodes:
                target_node = self.builder.graph.nodes[constructor[0]]
                if target_node.attributes.get("symbol_type") == "class":
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.instance_types[-1][target.id] = target_node.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._handle_dynamic_call(node):
            self.generic_visit(node)
            return

        resolution = self.builder._resolve_call_target(
            self.index,
            self.current_symbol_id,
            node.func,
            self.instance_types[-1],
        )
        call_name = _expr_name(node.func) or _safe_unparse(node.func)
        if resolution:
            target_id, confidence, method = resolution
            self.builder._add_edge(
                self.current_symbol_id,
                target_id,
                EDGE_CALLS,
                self.index.relative_path,
                getattr(node, "lineno", None),
                _line_end(node),
                "python_ast",
                confidence,
                attributes={"resolution": "resolved", "method": method, "call": call_name},
            )
        else:
            external_name = self.builder._external_call_name(self.index, call_name)
            if external_name:
                target_id = self.builder._ensure_external_symbol(external_name, dependency_type="call")
                self.builder._add_edge(
                    self.current_symbol_id,
                    target_id,
                    EDGE_CALLS,
                    self.index.relative_path,
                    getattr(node, "lineno", None),
                    _line_end(node),
                    "python_ast",
                    0.95,
                    attributes={"resolution": "external", "method": "import_binding", "call": external_name},
                )

        self._annotate_security_signal(node, call_name)
        self.generic_visit(node)

    def _annotate_sources(self, node: ast.AST, symbol_id: str) -> None:
        symbol = self.builder.graph.nodes[symbol_id]
        parameters = symbol.attributes.get("parameters", [])
        is_route = bool(symbol.attributes.get("entrypoint_types"))
        sources = list(symbol.attributes.get("sources", []))
        for parameter in parameters:
            lowered = parameter.lower()
            if is_route or any(token in lowered for token in ("request", "input", "payload", "body", "query", "param")):
                source = f"parameter:{parameter}"
                if source not in sources:
                    sources.append(source)
        symbol.attributes["sources"] = sources

    def _handle_dynamic_call(self, node: ast.Call) -> bool:
        call_name = _expr_name(node.func) or ""
        dynamic = call_name in DYNAMIC_CALL_NAMES
        if isinstance(node.func, ast.Subscript):
            base_name = _expr_name(node.func.value)
            dynamic = base_name in {"globals", "locals"} or isinstance(node.func.value, ast.Call)
        if isinstance(node.func, ast.Call) and (_expr_name(node.func.func) or "") == "getattr":
            dynamic = True
        if not dynamic:
            return False

        rendered = _safe_unparse(node.func)
        digest = hashlib.sha1(
            f"{self.index.relative_path}:{getattr(node, 'lineno', 0)}:{rendered}".encode("utf-8")
        ).hexdigest()[:12]
        target_id = f"external:dynamic:{digest}"
        candidates = self.builder._dynamic_candidates(self.index, self.current_symbol_id, node.func)
        self.builder.graph.add_node(ExternalDependencyNode(
            id=target_id,
            name=rendered,
            path=self.index.relative_path,
            line_start=getattr(node, "lineno", None),
            line_end=_line_end(node),
            attributes={
                "dependency_type": "dynamic_call",
                "resolution": "unknown",
                "candidate_symbol_ids": candidates,
                "uncertainty_reason": "dynamic_call_target_cannot_be_resolved_statically",
            },
        ))
        self.builder._add_edge(
            self.current_symbol_id,
            target_id,
            EDGE_CALLS,
            self.index.relative_path,
            getattr(node, "lineno", None),
            _line_end(node),
            "python_ast",
            0.2,
            uncertainty_reason="dynamic_call_target_cannot_be_resolved_statically",
            attributes={
                "resolution": "unknown",
                "call": rendered,
                "candidate_symbol_ids": candidates,
            },
        )
        symbol = self.builder.graph.nodes[self.current_symbol_id]
        uncertainties = symbol.attributes.setdefault("uncertainties", [])
        message = f"Unresolved dynamic call at {self.index.relative_path}:{getattr(node, 'lineno', '?')}: {rendered}"
        if message not in uncertainties:
            uncertainties.append(message)
        return True

    def _annotate_security_signal(self, node: ast.Call, call_name: str) -> None:
        symbol = self.builder.graph.nodes.get(self.current_symbol_id)
        if not symbol:
            return
        normalized = self.builder._external_call_name(self.index, call_name) or call_name
        for suffix, sink_type in SINK_SUFFIXES.items():
            if normalized == suffix or normalized.endswith(f".{suffix}") or call_name == suffix:
                signal = {"type": sink_type, "call": normalized, "line": getattr(node, "lineno", None)}
                if signal not in symbol.attributes.setdefault("sinks", []):
                    symbol.attributes["sinks"].append(signal)
                break
        for suffix, description in CONTROL_SUFFIXES.items():
            if normalized == suffix or normalized.endswith(f".{suffix}") or call_name.endswith(suffix):
                signal = {"type": description, "call": normalized, "line": getattr(node, "lineno", None)}
                if signal not in symbol.attributes.setdefault("controls", []):
                    symbol.attributes["controls"].append(signal)
                break
        if normalized.startswith("subprocess."):
            shell_keyword = next((keyword for keyword in node.keywords if keyword.arg == "shell"), None)
            if shell_keyword and isinstance(shell_keyword.value, ast.Constant) and shell_keyword.value.value is False:
                signal = {"type": "subprocess shell disabled", "call": normalized, "line": getattr(node, "lineno", None)}
                if signal not in symbol.attributes.setdefault("controls", []):
                    symbol.attributes["controls"].append(signal)


class ProjectGraphBuilder:
    """Build a deterministic V1 graph from repository files."""

    EXCLUDED_DISCOVERY_DIRS = {
        ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "__pycache__",
        "dist", "build", ".mypy_cache", ".pytest_cache", ".tox",
    }

    def __init__(self, root: str, extractors: Optional[Sequence[SourceExtractor]] = None):
        self.root = os.path.abspath(root)
        self.graph = ProjectGraph(root=self.root)
        self.extractors: Sequence[SourceExtractor] = extractors or (PythonAstExtractor(),)
        self.python_indexes: Dict[str, _PythonIndex] = {}
        self.module_to_file: Dict[str, str] = {}
        self.module_aliases: Dict[str, str] = {}
        self.symbol_by_name: Dict[str, str] = {}
        self.symbols_by_module: Dict[str, Dict[str, str]] = {}

    def build(self, source_paths: Optional[Sequence[str]] = None) -> ProjectGraph:
        paths = list(source_paths) if source_paths is not None else self._discover_paths()
        normalized_paths = []
        for path in paths:
            absolute = path if os.path.isabs(path) else os.path.join(self.root, path)
            if os.path.isfile(absolute):
                normalized_paths.append(os.path.abspath(absolute))

        for path in sorted(set(normalized_paths)):
            self._ensure_file_node(path)
            extractor = next((candidate for candidate in self.extractors if candidate.supports(path)), None)
            if extractor:
                extractor.index(self, path)

        self._build_module_aliases()
        for index in self.python_indexes.values():
            self._index_imports(index)
        for index in self.python_indexes.values():
            self._detect_python_entrypoints(index)
            _CallVisitor(self, index).visit(index.tree)
        for index in self.python_indexes.values():
            self._detect_django_entrypoints(index)

        self._detect_config_entrypoints(normalized_paths)
        self.graph.metadata.update({
            "builder": "ProjectGraphBuilder",
            "extractors": [extractor.name for extractor in self.extractors],
            "files_indexed": sum(1 for node in self.graph.nodes.values() if node.kind == "file"),
            "parse_errors": [
                {"path": node.path, "reason": node.attributes.get("parse_error")}
                for node in self.graph.nodes.values()
                if node.kind == "file" and node.attributes.get("parse_error")
            ],
        })
        return self.graph

    def _discover_paths(self) -> List[str]:
        discovered: List[str] = []
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [name for name in dirs if name not in self.EXCLUDED_DISCOVERY_DIRS]
            for filename in files:
                path = os.path.join(root, filename)
                if filename.endswith((".py", ".pyw")) or filename in CONFIG_FILENAMES:
                    discovered.append(path)
        return discovered

    def _ensure_file_node(self, path: str) -> str:
        relative = normalize_relative_path(self.root, path)
        node_id = f"file:{relative}"
        self.graph.add_node(FileNode(
            id=node_id,
            name=relative,
            path=relative,
            attributes={"classification": classify_file(relative)},
        ))
        return node_id

    def _module_name(self, relative_path: str) -> Tuple[str, bool]:
        path = relative_path.replace("\\", "/")
        is_package = path.endswith("/__init__.py") or path == "__init__.py"
        if path.endswith(".py"):
            path = path[:-3]
        elif path.endswith(".pyw"):
            path = path[:-4]
        parts = [part for part in path.split("/") if part]
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts), is_package

    def _index_python_file(self, path: str) -> None:
        relative = normalize_relative_path(self.root, path)
        file_id = self._ensure_file_node(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
            tree = ast.parse(content, filename=relative)
        except (OSError, SyntaxError) as exc:
            self.graph.nodes[file_id].attributes.update({
                "parse_error": f"{type(exc).__name__}: {exc}",
                "resolution": "unknown",
            })
            return

        module, is_package = self._module_name(relative)
        module_display = module or Path(relative).stem
        module_symbol_id = f"symbol:{module_display}.<module>"
        line_count = len(content.splitlines())
        self.graph.add_node(SymbolNode(
            id=module_symbol_id,
            name=f"{module_display}.<module>",
            path=relative,
            line_start=1 if line_count else None,
            line_end=line_count or None,
            attributes={
                "symbol_type": "module",
                "qualname": "<module>",
                "module": module,
                "file_classification": classify_file(relative),
                "sources": [],
                "sinks": [],
                "controls": [],
                "uncertainties": [],
            },
        ))
        self._add_edge(file_id, module_symbol_id, EDGE_CONTAINS, relative, 1, line_count or None, "python_ast", 1.0)
        index = _PythonIndex(
            path=path,
            relative_path=relative,
            module=module,
            is_package=is_package,
            tree=tree,
            content=content,
            file_node_id=file_id,
            module_symbol_id=module_symbol_id,
        )
        self.python_indexes[path] = index
        self.module_to_file[module] = file_id
        self.symbol_by_name[f"{module_display}.<module>"] = module_symbol_id
        self.symbols_by_module.setdefault(module, {})["<module>"] = module_symbol_id
        _DefinitionVisitor(self, index).visit(tree)

    def _build_module_aliases(self) -> None:
        for module in self.module_to_file:
            aliases = {module}
            parts = module.split(".") if module else []
            if parts and parts[0] in {"src", "lib", "python"}:
                aliases.add(".".join(parts[1:]))
            for alias in aliases:
                if alias:
                    self.module_aliases.setdefault(alias, module)

    def _canonical_module(self, imported: str) -> Optional[str]:
        if imported in self.module_to_file:
            return imported
        if imported in self.module_aliases:
            return self.module_aliases[imported]
        matches = [module for module in self.module_to_file if module.endswith(f".{imported}")]
        return matches[0] if len(matches) == 1 else None

    def _resolve_relative_import(self, index: _PythonIndex, module: Optional[str], level: int) -> str:
        if level <= 0:
            return module or ""
        package_parts = index.module.split(".") if index.is_package else index.module.split(".")[:-1]
        climb = max(0, level - 1)
        if climb:
            package_parts = package_parts[:-climb] if climb <= len(package_parts) else []
        if module:
            package_parts.extend(module.split("."))
        return ".".join(part for part in package_parts if part)

    def _index_imports(self, index: _PythonIndex) -> None:
        for node in ast.walk(index.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    binding = alias.asname or alias.name.split(".")[0]
                    index.imported_modules[binding] = alias.name
                    self._add_import_edge(index, alias.name, node)
            elif isinstance(node, ast.ImportFrom):
                module_name = self._resolve_relative_import(index, node.module, node.level)
                for alias in node.names:
                    binding = alias.asname or alias.name
                    if alias.name == "*":
                        index.imported_modules[binding] = module_name
                    else:
                        index.imported_symbols[binding] = (module_name, alias.name)
                    self._add_import_edge(index, module_name, node)

    def _add_import_edge(self, index: _PythonIndex, imported_module: str, node: ast.AST) -> None:
        canonical = self._canonical_module(imported_module)
        if canonical is not None:
            target = self.module_to_file[canonical]
            confidence = 1.0
            resolution = "local"
        else:
            top_level = imported_module.split(".")[0] if imported_module else "unknown"
            target = self._ensure_external_symbol(top_level, dependency_type="python_module")
            confidence = 1.0 if imported_module else 0.4
            resolution = "external" if imported_module else "unknown"
        self._add_edge(
            index.file_node_id,
            target,
            EDGE_IMPORTS,
            index.relative_path,
            getattr(node, "lineno", None),
            _line_end(node),
            "python_ast",
            confidence,
            uncertainty_reason=None if imported_module else "empty_or_unresolved_import",
            attributes={"module": imported_module, "resolution": resolution},
        )

    def _resolve_call_target(
        self,
        index: _PythonIndex,
        current_symbol_id: str,
        function: ast.AST,
        instance_types: Dict[str, str],
    ) -> Optional[Tuple[str, float, str]]:
        if isinstance(function, ast.Name):
            name = function.id
            current = self.graph.nodes.get(current_symbol_id)
            if current and current.attributes.get("symbol_type") == "method":
                class_name = current.name.rsplit(".", 1)[0]
                target = self.symbol_by_name.get(f"{class_name}.{name}")
                if target:
                    return target, 0.9, "same_class"
            target = self.symbol_by_name.get(f"{index.module}.{name}")
            if target:
                return target, 1.0, "same_module"
            imported = index.imported_symbols.get(name)
            if imported:
                module, symbol_name = imported
                canonical = self._canonical_module(module) or module
                target = self.symbol_by_name.get(f"{canonical}.{symbol_name}")
                if target:
                    return target, 1.0, "from_import"
            return None

        if isinstance(function, ast.Attribute):
            rendered = _expr_name(function)
            if not rendered:
                return None
            parts = rendered.split(".")
            if parts[0] == "self":
                current = self.graph.nodes.get(current_symbol_id)
                if current:
                    class_name = current.name.rsplit(".", 1)[0]
                    target = self.symbol_by_name.get(f"{class_name}.{'.'.join(parts[1:])}")
                    if target:
                        return target, 1.0, "self_method"
            if parts[0] in instance_types:
                target = self.symbol_by_name.get(f"{instance_types[parts[0]]}.{'.'.join(parts[1:])}")
                if target:
                    return target, 0.82, "local_instance_inference"
            if parts[0] in index.imported_modules:
                imported_module = index.imported_modules[parts[0]]
                canonical = self._canonical_module(imported_module) or imported_module
                target = self.symbol_by_name.get(f"{canonical}.{'.'.join(parts[1:])}")
                if target:
                    return target, 1.0, "module_import"
            if parts[0] in index.imported_symbols:
                module, symbol_name = index.imported_symbols[parts[0]]
                canonical = self._canonical_module(module) or module
                target = self.symbol_by_name.get(f"{canonical}.{symbol_name}.{'.'.join(parts[1:])}")
                if target:
                    return target, 0.95, "imported_class_or_object"
            direct = self.symbol_by_name.get(f"{index.module}.{rendered}")
            if direct:
                return direct, 1.0, "qualified_same_module"
        return None

    def _external_call_name(self, index: _PythonIndex, call_name: str) -> Optional[str]:
        parts = call_name.split(".")
        if not parts:
            return None
        first = parts[0]
        if first in index.imported_modules:
            imported = index.imported_modules[first]
            if self._canonical_module(imported) is None:
                return ".".join([imported] + parts[1:])
        if first in index.imported_symbols:
            module, symbol = index.imported_symbols[first]
            if self._canonical_module(module) is None:
                return ".".join([module, symbol] + parts[1:])
        if call_name in {"eval", "exec", "open", "input"}:
            return call_name
        return None

    def _ensure_external_symbol(self, name: str, dependency_type: str) -> str:
        node_id = f"external:{dependency_type}:{name}"
        self.graph.add_node(ExternalDependencyNode(
            id=node_id,
            name=name,
            attributes={"dependency_type": dependency_type, "resolution": "external"},
        ))
        return node_id

    def _dynamic_candidates(self, index: _PythonIndex, current_symbol_id: str, function: ast.AST) -> List[str]:
        rendered = _safe_unparse(function)
        candidates: List[str] = []
        current = self.graph.nodes.get(current_symbol_id)
        if "globals()" in rendered:
            candidates.extend(self.symbols_by_module.get(index.module, {}).values())
        elif rendered.startswith("getattr(self") and current:
            class_prefix = current.name.rsplit(".", 1)[0]
            candidates.extend(
                node_id for name, node_id in self.symbol_by_name.items()
                if name.startswith(f"{class_prefix}.")
            )
        return sorted(set(candidates))

    def _detect_python_entrypoints(self, index: _PythonIndex) -> None:
        classification = classify_file(index.relative_path)
        for node in ast.walk(index.tree):
            symbol_id = index.symbol_ids_by_ast.get(id(node))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and symbol_id:
                if classification == "test" and (node.name.startswith("test_") or node.name == "test"):
                    self._add_entrypoint(
                        index, symbol_id, f"test {self.graph.nodes[symbol_id].name}", "test", node,
                        method="python_test_convention", confidence=1.0, root_scope="test",
                    )
                self._detect_decorated_entrypoint(index, node, symbol_id)
            if isinstance(node, ast.If) and _is_main_guard(node):
                self._add_entrypoint(
                    index, index.module_symbol_id, f"python {index.relative_path}", "python_main", node,
                    method="python_ast_main_guard", confidence=1.0,
                )

        try:
            mode = os.stat(index.path).st_mode
            first_line = index.content.splitlines()[0] if index.content.splitlines() else ""
            if stat.S_IXUSR & mode and first_line.startswith("#!") and "python" in first_line.lower():
                self._add_entrypoint(
                    index, index.module_symbol_id, f"executable {index.relative_path}", "executable_script",
                    index.tree, method="executable_python_shebang", confidence=0.95,
                )
        except OSError:
            pass

        if os.path.basename(index.path) == "manage.py":
            self._add_entrypoint(
                index, index.module_symbol_id, "Django manage.py", "django_cli", index.tree,
                method="django_manage_filename", confidence=0.95,
            )

    def _detect_decorated_entrypoint(self, index: _PythonIndex, node: ast.AST, symbol_id: str) -> None:
        for decorator in getattr(node, "decorator_list", []):
            expression = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _expr_name(expression) or ""
            lowered = name.lower()
            if isinstance(decorator, ast.Call) and lowered.rsplit(".", 1)[-1] in {
                "get", "post", "put", "patch", "delete", "options", "head", "route", "api_route",
            }:
                route = _literal_string(decorator.args[0]) if decorator.args else None
                if route is not None:
                    method_name = lowered.rsplit(".", 1)[-1].upper()
                    if method_name in {"ROUTE", "API_ROUTE"}:
                        methods = self._keyword_string_list(decorator, "methods") or ["ANY"]
                    else:
                        methods = [method_name]
                    for http_method in methods:
                        self._add_entrypoint(
                            index, symbol_id, f"{http_method} {route}", "http_route", decorator,
                            method="python_route_decorator", confidence=1.0,
                            extra={"framework_hint": "FastAPI/Flask", "http_method": http_method, "route": route},
                        )
                    continue
            if lowered.endswith((".command", ".callback")) or lowered in {"click.command", "typer.command"}:
                self._add_entrypoint(
                    index, symbol_id, f"CLI {self.graph.nodes[symbol_id].name}", "cli_command", decorator,
                    method="python_cli_decorator", confidence=0.95,
                )

    def _keyword_string_list(self, call: ast.Call, keyword_name: str) -> List[str]:
        keyword = next((item for item in call.keywords if item.arg == keyword_name), None)
        if keyword is None:
            return []
        if isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
            return [value for item in keyword.value.elts if (value := _literal_string(item))]
        value = _literal_string(keyword.value)
        return [value] if value else []

    def _detect_django_entrypoints(self, index: _PythonIndex) -> None:
        if not index.relative_path.endswith(("urls.py", "urls/__init__.py")):
            return
        for node in ast.walk(index.tree):
            if not isinstance(node, ast.Call) or (_expr_name(node.func) or "").split(".")[-1] not in {"path", "re_path"}:
                continue
            if len(node.args) < 2:
                continue
            route = _literal_string(node.args[0])
            resolution = self._resolve_call_target(index, index.module_symbol_id, node.args[1], {})
            if route is None or resolution is None:
                continue
            self._add_entrypoint(
                index, resolution[0], f"Django {route}", "http_route", node,
                method="django_urlpattern_ast", confidence=resolution[1],
                extra={"framework_hint": "Django", "route": route, "http_method": "ANY"},
            )

    def _add_entrypoint(
        self,
        index: _PythonIndex,
        symbol_id: str,
        label: str,
        entrypoint_type: str,
        evidence_node: ast.AST,
        *,
        method: str,
        confidence: float,
        root_scope: str = "runtime",
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        line = getattr(evidence_node, "lineno", 1)
        digest = hashlib.sha1(f"{entrypoint_type}:{index.relative_path}:{line}:{label}".encode("utf-8")).hexdigest()[:12]
        entrypoint_id = f"entrypoint:{digest}"
        attributes = {
            "entrypoint_type": entrypoint_type,
            "detection_method": method,
            "confidence": confidence,
            "root_scope": root_scope,
        }
        attributes.update(extra or {})
        self.graph.add_node(EntrypointNode(
            id=entrypoint_id,
            name=label,
            path=index.relative_path,
            line_start=line,
            line_end=_line_end(evidence_node),
            attributes=attributes,
        ))
        self._add_edge(
            entrypoint_id, symbol_id, EDGE_EXPOSES, index.relative_path, line, _line_end(evidence_node),
            method, confidence, attributes={"resolution": "resolved"},
        )
        symbol = self.graph.nodes.get(symbol_id)
        if symbol:
            entrypoint_types = symbol.attributes.setdefault("entrypoint_types", [])
            if entrypoint_type not in entrypoint_types:
                entrypoint_types.append(entrypoint_type)
            if root_scope == "runtime" and isinstance(evidence_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = symbol.attributes.get("parameters", [])
                for parameter in parameters:
                    source = f"parameter:{parameter}"
                    if source not in symbol.attributes.setdefault("sources", []):
                        symbol.attributes["sources"].append(source)
        return entrypoint_id

    def _detect_config_entrypoints(self, paths: Sequence[str]) -> None:
        by_name = {normalize_relative_path(self.root, path): path for path in paths}
        for relative, path in by_name.items():
            name = os.path.basename(path)
            if name == "pyproject.toml":
                self._detect_pyproject_scripts(path, relative)
            elif name == "package.json":
                self._detect_package_scripts(path, relative)
            elif name == "Dockerfile" or name.lower().endswith("dockerfile"):
                self._detect_docker_commands(path, relative)
            elif name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
                self._detect_compose_commands(path, relative)

    def _detect_pyproject_scripts(self, path: str, relative: str) -> None:
        if tomllib is None:
            return
        try:
            with open(path, "rb") as handle:
                payload = tomllib.load(handle)
        except (OSError, ValueError):
            return
        scripts = payload.get("project", {}).get("scripts", {})
        scripts.update(payload.get("project", {}).get("gui-scripts", {}))
        for command, target in scripts.items():
            if not isinstance(target, str):
                continue
            module, _, symbol_name = target.partition(":")
            canonical = self._canonical_module(module) or module
            symbol_id = self.symbol_by_name.get(f"{canonical}.{symbol_name}") if symbol_name else None
            self._add_config_entrypoint(
                relative, f"CLI {command}", "cli_command", "pyproject_project_scripts", 0.98,
                target_symbol_id=symbol_id, command=target,
            )

    def _detect_package_scripts(self, path: str, relative: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            return
        for script_name, command in (payload.get("scripts") or {}).items():
            if script_name not in {"start", "serve", "dev", "worker"} or not isinstance(command, str):
                continue
            self._add_config_entrypoint(
                relative, f"npm {script_name}", "npm_script", "package_json_script", 0.9,
                command=command,
            )

    def _detect_docker_commands(self, path: str, relative: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except OSError:
            return
        for line_number, line in enumerate(lines, 1):
            if re.match(r"^\s*(CMD|ENTRYPOINT)\b", line, re.IGNORECASE):
                self._add_config_entrypoint(
                    relative, line.strip(), "container_command", "dockerfile_command", 0.95,
                    line=line_number, command=line.strip(),
                )

    def _detect_compose_commands(self, path: str, relative: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except OSError:
            return
        for line_number, line in enumerate(lines, 1):
            match = re.match(r"^\s*(?:command|entrypoint)\s*:\s*(.+?)\s*$", line)
            if match:
                self._add_config_entrypoint(
                    relative, f"compose {match.group(1)}", "container_command", "compose_command", 0.82,
                    line=line_number, command=match.group(1),
                )

    def _add_config_entrypoint(
        self,
        relative: str,
        label: str,
        entrypoint_type: str,
        method: str,
        confidence: float,
        *,
        line: int = 1,
        target_symbol_id: Optional[str] = None,
        command: Optional[str] = None,
    ) -> str:
        digest = hashlib.sha1(f"{relative}:{line}:{label}".encode("utf-8")).hexdigest()[:12]
        node_id = f"entrypoint:{digest}"
        self.graph.add_node(EntrypointNode(
            id=node_id,
            name=label,
            path=relative,
            line_start=line,
            line_end=line,
            attributes={
                "entrypoint_type": entrypoint_type,
                "detection_method": method,
                "confidence": confidence,
                "root_scope": "runtime",
                "command": command,
                "resolution": "resolved" if target_symbol_id else "unknown",
            },
        ))
        if target_symbol_id:
            self._add_edge(
                node_id, target_symbol_id, EDGE_EXPOSES, relative, line, line, method, confidence,
                attributes={"resolution": "resolved"},
            )
        return node_id

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        path: str,
        line_start: Optional[int],
        line_end: Optional[int],
        extractor: str,
        confidence: float,
        *,
        uncertainty_reason: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.graph.add_edge(GraphEdge(
            source=source,
            target=target,
            type=edge_type,
            evidence=EdgeEvidence(
                path=path,
                line_start=line_start,
                line_end=line_end,
                extractor=extractor,
                confidence=max(0.0, min(1.0, float(confidence))),
                uncertainty_reason=uncertainty_reason,
            ),
            attributes=attributes or {},
        ))
