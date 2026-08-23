#!/usr/bin/env python3
"""AutoPentestX - Plugin Loader"""

from __future__ import annotations

import importlib.util
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PluginMeta:
    name: str
    description: str
    version: str = '1.0.0'
    author: str = 'community'
    tags: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)


class PluginBase(ABC):
    """All plugins must inherit this class and set ``meta`` as a class attribute."""

    meta: PluginMeta

    @abstractmethod
    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]: ...

    def validate(self, target: str) -> bool:
        return True


class PluginLoader:
    def __init__(self, plugin_dir: str = 'plugins') -> None:
        self.plugin_dir = os.path.abspath(plugin_dir)
        self._registry: Dict[str, type] = {}

    def discover(self) -> List[str]:
        self._registry.clear()
        found: List[str] = []
        if not os.path.isdir(self.plugin_dir):
            return found
        for filename in sorted(os.listdir(self.plugin_dir)):
            if not filename.endswith('.py') or filename.startswith('_'):
                continue
            path = os.path.join(self.plugin_dir, filename)
            module = self._load_module(filename[:-3], path)
            if module is None:
                continue
            plugin_cls = getattr(module, 'Plugin', None)
            if plugin_cls is None:
                continue
            if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, PluginBase)):
                continue
            meta = getattr(plugin_cls, 'meta', None)
            if not isinstance(meta, PluginMeta):
                continue
            self._registry[meta.name] = plugin_cls
            found.append(meta.name)
        return found

    @staticmethod
    def _load_module(name: str, path: str):
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            sys.modules.setdefault(f'autopentestx.plugins.{name}', mod)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            return mod
        except Exception as exc:
            print(f'[plugin_loader] WARNING: could not load {path!r}: {exc}')
            return None

    def load(self, name: str) -> PluginBase:
        if not self._registry:
            self.discover()
        cls = self._registry.get(name)
        if cls is None:
            raise KeyError(f'Plugin {name!r} not found. Available: {sorted(self._registry)}')
        return cls()

    def run_all(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, List[Dict]]:
        if not self._registry:
            self.discover()
        context = context or {}
        aggregated: Dict[str, List[Dict]] = {}
        for name, cls in self._registry.items():
            instance: PluginBase = cls()
            try:
                if not instance.validate(target):
                    aggregated[name] = [{'skipped': True, 'reason': 'validate() returned False'}]
                    continue
                result = instance.run(target, context)
                aggregated[name] = [result] if not isinstance(result, list) else result
            except Exception as exc:
                aggregated[name] = [{'error': str(exc), 'plugin': name}]
        return aggregated

    def list_plugins(self) -> None:
        if not self._registry:
            self.discover()
        if not self._registry:
            print('No plugins found in', self.plugin_dir)
            return
        name_w = max(len('Plugin'), max(len(n) for n in self._registry))
        ver_w  = max(len('Version'), max(len(cls.meta.version) for cls in self._registry.values()))
        auth_w = max(len('Author'),  max(len(cls.meta.author)  for cls in self._registry.values()))
        header = (f'{"Plugin":<{name_w}}  {"Version":<{ver_w}}  '
                  f'{"Author":<{auth_w}}  Tags  Description')
        sep = '-' * max(80, len(header))
        print('\n' + sep)
        print(header)
        print(sep)
        for name in sorted(self._registry):
            meta = self._registry[name].meta
            tags = ', '.join(meta.tags) if meta.tags else '—'
            print(f'{name:<{name_w}}  {meta.version:<{ver_w}}  '
                  f'{meta.author:<{auth_w}}  [{tags}]  {meta.description}')
        print(sep + '\n')
