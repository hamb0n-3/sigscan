\
from __future__ import annotations
import importlib
import pkgutil
from typing import Dict, List, Type

from ..parsers.base import ParserPlugin
from ..patterns.base import PatternPlugin


def _discover_package_classes(pkg, base_cls) -> Dict[str, Type]:
    discovered: Dict[str, Type] = {}
    for m in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
        module = importlib.import_module(m.name)
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if isinstance(obj, type) and issubclass(obj, base_cls) and obj is not base_cls:
                name = getattr(obj, "NAME", obj.__name__).lower()
                discovered[name] = obj
    return discovered


def discover_parser_plugins() -> Dict[str, ParserPlugin]:
    from .. import parsers as parsers_pkg  # lazy import
    classes = _discover_package_classes(parsers_pkg, ParserPlugin)
    # Instantiate
    return {name: cls() for name, cls in classes.items()}


def discover_pattern_plugins() -> Dict[str, PatternPlugin]:
    from .. import patterns as patterns_pkg  # lazy import
    classes = _discover_package_classes(patterns_pkg, PatternPlugin)
    return {name: cls() for name, cls in classes.items()}


def select_pattern_plugins(all_plugins: Dict[str, PatternPlugin], selector: str) -> Dict[str, PatternPlugin]:
    selector = (selector or "").strip().lower()
    if selector == "all" or selector == "*":
        return dict(all_plugins)
    selected = {}
    for token in (t.strip() for t in selector.split(",") if t.strip()):
        if token in all_plugins:
            selected[token] = all_plugins[token]
    return selected
