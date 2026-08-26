"""Measurement-integrity invariants.

These tests do not check that code works. They check that a property holds,
in the same spirit as the authorization invariants in itops-mcp-gateway.

The property: nothing the pipeline runs may reach the ground-truth labels. If
a triage agent can read the answer key, every number this project reports is
worthless, and the failure would be silent. So it is enforced here rather than
left to discipline.

Imports are found by parsing the AST rather than searching text, so a comment
or a docstring mentioning the module does not trip the test, and an import
written unusually does not slip past it.
"""

import ast
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "soc_triage"

FORBIDDEN_PREFIX = "soc_triage.evaluation"
GUARDED_SUBPACKAGES = ("pipeline", "corpus", "enrichment", "api")


def _module_paths(subpackage: str) -> list[Path]:
    return sorted((PACKAGE_ROOT / subpackage).rglob("*.py"))


def _imported_modules(source: str, module_package: str) -> set[str]:
    """Every module name a source file imports, absolute and relative."""
    tree = ast.parse(source)
    found: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative import: resolve against the containing package.
                parts = module_package.split(".")
                base = parts[: len(parts) - node.level + 1]
                resolved = ".".join(base + ([node.module] if node.module else []))
                found.add(resolved)
            elif node.module:
                found.add(node.module)

    return found


@pytest.mark.parametrize("subpackage", GUARDED_SUBPACKAGES)
def test_runtime_code_cannot_import_labels(subpackage: str) -> None:
    """No module the pipeline runs may import the evaluation package."""
    offenders: list[str] = []

    for path in _module_paths(subpackage):
        relative = path.relative_to(PACKAGE_ROOT.parent)
        module_package = ".".join(relative.with_suffix("").parts[:-1])
        imports = _imported_modules(path.read_text(encoding="utf-8"), module_package)

        for imported in imports:
            if imported == FORBIDDEN_PREFIX or imported.startswith(
                FORBIDDEN_PREFIX + "."
            ):
                offenders.append(f"{relative} imports {imported}")

    assert not offenders, (
        "Runtime code must not import ground-truth labels:\n  "
        + "\n  ".join(offenders)
    )


def test_detector_catches_a_planted_violation(tmp_path: Path) -> None:
    """The guard above must actually be capable of failing.

    A test that can only pass is not a gate. This plants each import form and
    confirms the AST walker sees it.
    """
    cases = {
        "plain": "import soc_triage.evaluation.labels",
        "from": "from soc_triage.evaluation.labels import AlertLabel",
        "aliased": "import soc_triage.evaluation.labels as answers",
        "package_only": "from soc_triage.evaluation import labels",
    }

    for name, source in cases.items():
        imports = _imported_modules(source, "soc_triage.pipeline")
        hit = any(
            i == FORBIDDEN_PREFIX or i.startswith(FORBIDDEN_PREFIX + ".")
            for i in imports
        )
        assert hit, f"walker missed the {name} import form: {source}"


def test_relative_import_is_resolved() -> None:
    """A relative import from inside pipeline/ resolves to its absolute name."""
    imports = _imported_modules(
        "from ..evaluation.labels import AlertLabel", "soc_triage.pipeline"
    )
    assert FORBIDDEN_PREFIX + ".labels" in imports, imports
